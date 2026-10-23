//! AB6-T5 against a real database: while a webhook target's breaker is open,
//! a delivery is queued again for when the breaker may let a call through,
//! and no attempt is counted.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-events --test delivery_breaker
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_events::delivery::{defer_if_open, endpoint};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// A subscription and one pending delivery for it.
async fn seed_delivery(db: &DbPool) -> (Uuid, Uuid) {
    let owner = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, 'ab6', true)",
    )
    .bind(owner)
    .bind(format!("ab6-{owner}@test.invalid"))
    .execute(db)
    .await
    .unwrap();
    let subscription: Uuid = sqlx::query_scalar(
        "INSERT INTO event_subscription (name, kind, owner_ref) \
         VALUES ($1, 'job', $2) RETURNING id",
    )
    .bind(format!("ab6-{owner}"))
    .bind(owner)
    .fetch_one(db)
    .await
    .unwrap();
    let delivery: Uuid = sqlx::query_scalar(
        "INSERT INTO event_delivery \
            (subscription_ref, event_id, event_entity_logicalname, event_record_id, event_operation) \
         VALUES ($1, $2, 'account', $3, 'create') RETURNING id",
    )
    .bind(subscription)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .fetch_one(db)
    .await
    .unwrap();
    (subscription, delivery)
}

#[tokio::test]
async fn webhook_skips_open_breaker_without_attempt() {
    let db = skip_if_no_db!(test_db().await);
    let (subscription, delivery) = seed_delivery(&db).await;
    let url = reqwest::Url::parse("https://hooks.example.com/in").unwrap();
    let service = endpoint(subscription, &url);

    // Closed: the delivery may be tried now.
    assert!(!defer_if_open(&db, delivery, &service).await.unwrap());

    for _ in 0..30 {
        service.breaker.record(false);
    }
    assert!(
        defer_if_open(&db, delivery, &service).await.unwrap(),
        "open: deferred"
    );

    let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM event_delivery WHERE id = $1")
        .bind(delivery)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(attempts, 0, "a deferred delivery is not counted");

    let later: bool = sqlx::query_scalar(
        "SELECT run_at > now() + interval '5 seconds' FROM apalis.jobs \
          WHERE job::text LIKE '%' || $1 || '%' ORDER BY run_at DESC LIMIT 1",
    )
    .bind(delivery.to_string())
    .fetch_one(&db)
    .await
    .expect("the delivery was queued again");
    assert!(later, "queued for when the breaker may let a call through");

    // Another subscription's endpoint on the same host is not affected.
    let (other, other_delivery) = seed_delivery(&db).await;
    assert!(
        !defer_if_open(&db, other_delivery, &endpoint(other, &url))
            .await
            .unwrap()
    );
}
