//! G17-T16: staff self-service end to end (G17-T8). Each person reads only
//! their own published shifts and preferences; a shift goes to a colleague
//! at once when the colleague is free and their rules hold, and waits for a
//! planner when the colleague already works then; a shift that is not the
//! caller's, a colleague outside the group and the caller themself are
//! refused; a planner's decision is final.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

async fn group(app: &TestApp, members: &[Uuid]) -> Uuid {
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO wfm_planning_group (id, name, is_active, row_version) \
         VALUES (uuidv7(), 'Team', true, 0) RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    for member in members {
        sqlx::query(
            "INSERT INTO wfm_group_member (id, planning_group_ref, user_ref, is_active, row_version) \
             VALUES (uuidv7(), $1, $2, true, 0)",
        )
        .bind(group)
        .bind(member)
        .execute(app.db())
        .await
        .unwrap();
    }
    group
}

fn at(day: u32, hour: u32) -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(2027, 3, day)
        .and_then(|d| d.and_hms_opt(hour, 0, 0))
        .unwrap()
        .and_utc()
}

async fn shift(app: &TestApp, schedule: Uuid, user: Uuid, day: u32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO wfm_shift_assignment (id, schedule_ref, user_ref, start_at, end_at, \
             activity, is_active, row_version) \
         VALUES (uuidv7(), $1, $2, $3, $4, 'work', true, 0) RETURNING id",
    )
    .bind(schedule)
    .bind(user)
    .bind(at(day, 8))
    .bind(at(day, 16))
    .fetch_one(app.db())
    .await
    .unwrap()
}

fn owners(body: &Value) -> Vec<String> {
    body.as_array()
        .unwrap_or_else(|| panic!("a list: {body}"))
        .iter()
        .map(|a| a["user_id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

// feature: G17
// negative: POST /api/v1/workforce/swaps, POST /api/v1/workforce/swaps/{id}/decide, PUT /api/v1/workforce/me/preferences
#[test]
fn self_service_scoping_and_swaps() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["workforce"]).await;
        let a = seed_user(app.db(), "wfm-ss-a").await;
        let b = seed_user(app.db(), "wfm-ss-b").await;
        let outsider = seed_user(app.db(), "wfm-ss-out").await;
        let team = group(&app, &[a.id, b.id]).await;
        let _other = group(&app, &[outsider.id]).await;

        let schedule: Uuid = sqlx::query_scalar(
            "INSERT INTO wfm_schedule (id, planning_group_ref, period_from, period_to, status, \
                 is_active, row_version) \
             VALUES (uuidv7(), $1, $2, $3, 'published', true, 0) RETURNING id",
        )
        .bind(team)
        .bind(at(7, 0))
        .bind(at(13, 23))
        .fetch_one(app.db())
        .await
        .unwrap();
        let a_sunday = shift(&app, schedule, a.id, 7).await;
        let a_monday = shift(&app, schedule, a.id, 8).await;
        let _b_sunday = shift(&app, schedule, b.id, 7).await;

        // Each person sees only their own shifts.
        let week = "/api/v1/workforce/me/schedule?from=2027-03-07&to=2027-03-13";
        let (status, mine) = app.request_as(&a.cookie, Method::GET, week, None).await;
        assert_eq!(status, StatusCode::OK, "{mine}");
        assert_eq!(owners(&mine), vec![a.id.to_string(); 2]);
        let (_, theirs) = app.request_as(&b.cookie, Method::GET, week, None).await;
        assert_eq!(owners(&theirs), vec![b.id.to_string()]);
        let (status, body) = app
            .request_as(
                &a.cookie,
                Method::GET,
                "/api/v1/workforce/me/schedule?from=2027-03-13&to=2027-03-07",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // Preferences: validated, and only the caller's own rows change.
        let (status, body) = app
            .request_as(
                &a.cookie,
                Method::PUT,
                "/api/v1/workforce/me/preferences",
                Some(json!({ "preferences": [{ "weekday": 7 }] })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, body) = app
            .request_as(
                &a.cookie,
                Method::PUT,
                "/api/v1/workforce/me/preferences",
                Some(json!({ "preferences": [
                    { "weekday": 0, "preferred_start": "09:00" },
                    { "weekday": 4, "day_off": true }
                ] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE user_ref = $1), COUNT(*) FILTER (WHERE user_ref = $2) \
               FROM wfm_preference",
        )
        .bind(a.id)
        .bind(b.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(counts, (2, 0));

        // Refusals: someone else's shift, an outsider, oneself.
        let swap = |assignment: Uuid, to: Uuid| {
            json!({ "assignment_id": assignment, "to_user_id": to, "reason": "family" })
        };
        let (status, body) = app
            .request_as(
                &b.cookie,
                Method::POST,
                "/api/v1/workforce/swaps",
                Some(swap(a_sunday, a.id)),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        for to in [outsider.id, a.id] {
            let (status, body) = app
                .request_as(
                    &a.cookie,
                    Method::POST,
                    "/api/v1/workforce/swaps",
                    Some(swap(a_sunday, to)),
                )
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{to}: {body}");
        }

        // B already works Sunday: the swap waits for a planner.
        let (status, waiting) = app
            .request_as(
                &a.cookie,
                Method::POST,
                "/api/v1/workforce/swaps",
                Some(swap(a_sunday, b.id)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{waiting}");
        assert_eq!(waiting["status"], "requested", "{waiting}");
        assert!(waiting["waiting_because"].is_string(), "{waiting}");

        // B is free Monday: the swap applies at once.
        let (status, approved) = app
            .request_as(
                &a.cookie,
                Method::POST,
                "/api/v1/workforce/swaps",
                Some(swap(a_monday, b.id)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["status"], "approved", "{approved}");
        let (_, mine) = app.request_as(&a.cookie, Method::GET, week, None).await;
        assert_eq!(owners(&mine).len(), 1, "{mine}");
        let (_, theirs) = app.request_as(&b.cookie, Method::GET, week, None).await;
        assert_eq!(owners(&theirs), vec![b.id.to_string(); 2], "{theirs}");

        // The planner rejects the waiting swap; a second decision conflicts.
        let waiting_id = waiting["swap_id"].as_str().unwrap();
        let decide = format!("/api/v1/workforce/swaps/{waiting_id}/decide");
        let (status, body) = app
            .request(
                Method::POST,
                &decide,
                Some(json!({ "approve": false, "reason": "short that day" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "rejected", "{body}");
        let (status, body) = app
            .request(Method::POST, &decide, Some(json!({ "approve": true })))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let owner: Uuid =
            sqlx::query_scalar("SELECT user_ref FROM wfm_shift_assignment WHERE id = $1")
                .bind(a_sunday)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(owner, a.id, "a rejected swap leaves the shift where it was");
    });
}
