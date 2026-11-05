//! G17-T16: intraday management end to end (G17-T9). Volume running at three
//! times the forecast makes the intraday tick propose overtime for the rest
//! of the day, once; a planner sends it to the people off shift; the first
//! of them to accept gets the shift, and nobody after them can.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::EngineState;
use attome_testapp::{TestApp, seed_user};
use attome_types::AppError;
use attome_workforce::intraday::{ActualsSource, tick};
use attome_workforce::staffing::ChannelKind;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// Forecast contacts per half hour.
const FORECAST: f64 = 20.0;

/// Three times the forecast so far.
struct Busy {
    midnight: DateTime<Utc>,
}

impl ActualsSource for Busy {
    async fn volume(
        &self,
        _state: &EngineState,
        _channel: ChannelKind,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<f64, AppError> {
        assert_eq!(from, self.midnight);
        let intervals = (to - from).num_minutes() / 30;
        Ok(3.0 * FORECAST * intervals as f64)
    }
}

// feature: G17
// negative: POST /api/v1/workforce/offers/{id}/accept
#[test]
fn overtime_proposal_when_actuals_exceed_forecast() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["workforce"]).await;
        let on_shift = seed_user(app.db(), "wfm-id-on").await;
        let first = seed_user(app.db(), "wfm-id-first").await;
        let second = seed_user(app.db(), "wfm-id-second").await;
        let outsider = seed_user(app.db(), "wfm-id-out").await;

        let midnight = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        let now = midnight + Duration::hours(10);

        let group: Uuid = sqlx::query_scalar(
            "INSERT INTO wfm_planning_group (id, name, channel, interval_minutes, aht_seconds, \
                 service_level_target_pct, service_level_seconds, intraday_enabled, is_active, \
                 row_version) \
             VALUES (uuidv7(), 'Voice', 'voice', '30', 180, 80, 20, true, true, 0) RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        for member in [on_shift.id, first.id, second.id] {
            sqlx::query(
                "INSERT INTO wfm_group_member (id, planning_group_ref, user_ref, is_active, \
                     row_version) VALUES (uuidv7(), $1, $2, true, 0)",
            )
            .bind(group)
            .bind(member)
            .execute(app.db())
            .await
            .unwrap();
        }
        let schedule: Uuid = sqlx::query_scalar(
            "INSERT INTO wfm_schedule (id, planning_group_ref, period_from, period_to, status, \
                 is_active, row_version) \
             VALUES (uuidv7(), $1, $2, $3, 'published', true, 0) RETURNING id",
        )
        .bind(group)
        .bind(midnight)
        .bind(midnight + Duration::hours(23))
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO wfm_shift_assignment (id, schedule_ref, user_ref, start_at, end_at, \
                 activity, is_active, row_version) \
             VALUES (uuidv7(), $1, $2, $3, $4, 'work', true, 0)",
        )
        .bind(schedule)
        .bind(on_shift.id)
        .bind(midnight + Duration::hours(8))
        .bind(midnight + Duration::hours(18))
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO wfm_forecast_interval (id, planning_group_ref, interval_start, volume, \
                 digital_share, is_active, row_version) \
             SELECT uuidv7(), $1, $2 + make_interval(mins => 30 * g), $3, 0, true, 0 \
               FROM generate_series(0, 47) AS g",
        )
        .bind(group)
        .bind(midnight)
        .bind(FORECAST)
        .execute(app.db())
        .await
        .unwrap();

        let busy = Busy { midnight };
        let made = tick(&app.state, &busy, now).await.unwrap();
        assert!(made >= 1, "volume at 300% proposes overtime");
        let offers: Vec<(Uuid, String, String, DateTime<Utc>, i64)> = sqlx::query_as(
            "SELECT id, kind::text, status::text, start_at::timestamptz, people::int8 \
               FROM wfm_offer WHERE planning_group_ref = $1 ORDER BY start_at",
        )
        .bind(group)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert!(!offers.is_empty());
        for (_, kind, status, start, people) in &offers {
            assert_eq!(kind, "overtime", "short of people, never over");
            assert_eq!(status, "proposed");
            assert!(*start >= now, "only the rest of the day: {start}");
            assert!(*people >= 2, "a gap of more than one person: {people}");
        }
        // The same tick again proposes nothing new.
        assert_eq!(tick(&app.state, &busy, now).await.unwrap(), 0);

        let offer = offers[0].0;
        let accept = format!("/api/v1/workforce/offers/{offer}/accept");
        // Not sent yet: nobody can take it.
        let (status, body) = app
            .request_as(&first.cookie, Method::POST, &accept, None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let (status, sent) = app
            .request(
                Method::POST,
                &format!("/api/v1/workforce/offers/{offer}/send"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        assert_eq!(sent["status"], "sent", "{sent}");
        assert_eq!(sent["told"], 2, "the two people off shift: {sent}");

        let (status, body) = app
            .request_as(&outsider.cookie, Method::POST, &accept, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "not in the group: {body}");
        let (status, taken) = app
            .request_as(&first.cookie, Method::POST, &accept, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{taken}");
        assert_eq!(taken["status"], "taken", "{taken}");
        let (status, body) = app
            .request_as(&second.cookie, Method::POST, &accept, None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "taken first: {body}");

        let booked: (i64, bool) = sqlx::query_as(
            "SELECT COUNT(*), bool_and(booking_id IS NOT NULL) FROM wfm_shift_assignment \
              WHERE schedule_ref = $1 AND user_ref = $2 AND start_at::timestamptz = $3",
        )
        .bind(schedule)
        .bind(first.id)
        .bind(offers[0].3)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(booked, (1, true), "the overtime shift is added and booked");
    });
}
