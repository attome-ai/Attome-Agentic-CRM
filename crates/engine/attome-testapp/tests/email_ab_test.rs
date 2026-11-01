//! E4-T1: once an email A/B test's window has passed, the variant with the
//! clearly better open rate goes to the recipients held back for it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use chrono::{Duration, Utc};
use uuid::Uuid;

/// A send whose test went out `hours_ago`, with 200 tracked recipients per
/// variant (A opened by 20, B by 80) and 300 held.
async fn finished_test(app: &TestApp, hours_ago: i64) -> Uuid {
    let send: Uuid = sqlx::query_scalar(
        "INSERT INTO email_campaign_send \
           (list_id, subject, html_body, text_body, purpose_key, ab_metric, \
            ab_window_minutes, ab_fallback, created_at) \
         VALUES ($1, 'Offer', '<p>A</p>', 'A', 'promotions', 'opens', 240, 'leader', \
                 now() - make_interval(hours => $2)) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(i32::try_from(hours_ago).unwrap())
    .fetch_one(app.db())
    .await
    .unwrap();
    for (variant, opened) in [("A", 20), ("B", 80)] {
        sqlx::query(
            "INSERT INTO email_campaign_recipient \
               (send_id, subject_entity, subject_id, email, unsubscribe_token, variant, \
                status, tracked, attempted_at, opened_at) \
             SELECT $1, 'contact', uuidv7(), $2 || g || '@example.test', \
                    md5($2 || g || $1::text) || md5(g || $2 || $1::text), $2, 'sent', true, \
                    now(), CASE WHEN g <= $3 THEN now() END \
               FROM generate_series(1, 200) AS g",
        )
        .bind(send)
        .bind(variant)
        .bind(opened)
        .execute(app.db())
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO email_campaign_recipient \
           (send_id, subject_entity, subject_id, email, unsubscribe_token, status) \
         SELECT $1, 'contact', uuidv7(), 'held' || g || '@example.test', \
                md5('held' || g || $1::text) || md5(g || 'held' || $1::text), 'held' \
           FROM generate_series(1, 300) AS g",
    )
    .bind(send)
    .execute(app.db())
    .await
    .unwrap();
    send
}

async fn held_and_released(app: &TestApp, send: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE status = 'held'), \
                COUNT(*) FILTER (WHERE status = 'pending' AND variant = 'B' AND NOT tracked) \
           FROM email_campaign_recipient WHERE send_id = $1",
    )
    .bind(send)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: E4
#[test]
fn the_winning_variant_goes_to_the_held_recipients() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let send = finished_test(&app, 5).await;
        let started = Utc::now() - Duration::hours(5);
        let decided =
            attome_marketing::email_ab::decide(&app.state, send, started, "opens", 240, "leader")
                .await
                .unwrap();
        assert!(decided);
        assert_eq!(held_and_released(&app, send).await, (0, 300));
        let winner: Option<String> =
            sqlx::query_scalar("SELECT ab_winner FROM email_campaign_send WHERE id = $1")
                .bind(send)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(winner.as_deref(), Some("B"));
        // Decided once.
        assert!(
            !attome_marketing::email_ab::decide(&app.state, send, started, "opens", 240, "leader")
                .await
                .unwrap()
        );
    });
}

// feature: E4
#[test]
fn nothing_is_released_before_the_window_has_passed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let send = finished_test(&app, 1).await;
        let started = Utc::now() - Duration::hours(1);
        let decided =
            attome_marketing::email_ab::decide(&app.state, send, started, "opens", 240, "leader")
                .await
                .unwrap();
        assert!(!decided);
        assert_eq!(held_and_released(&app, send).await, (300, 0));
    });
}
