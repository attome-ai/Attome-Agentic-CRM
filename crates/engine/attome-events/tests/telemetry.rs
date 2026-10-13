//! M62 E1 — the backlog-gauge queries (`telemetry::read_gauges`) run against
//! the real schema: the dead-letter/retrying counts come back per kind, and
//! both lag queries (entity change feed for `webhook`, audit ledger for
//! `audit`) execute with a subscription of each kind present.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-events --test telemetry -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_events::telemetry::{self, LAG_CAP};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

async fn seed_owner(db: &DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("events-telemetry-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

async fn seed_subscription(db: &DbPool, owner_ref: Uuid, kind: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO event_subscription \
            (name, kind, target_url, webhook_secret_encrypted, owner_ref) \
         VALUES ($1, $2, 'http://127.0.0.1:9/unreachable', 'not-a-real-ciphertext', $3) \
         RETURNING id",
    )
    .bind(format!("telemetry-test-{}", Uuid::now_v7()))
    .bind(kind)
    .bind(owner_ref)
    .fetch_one(db)
    .await
    .expect("insert throwaway subscription")
}

async fn seed_delivery(db: &DbPool, subscription_ref: Uuid, status: &str) {
    sqlx::query(
        "INSERT INTO event_delivery \
            (subscription_ref, event_id, event_entity_logicalname, event_record_id, \
             event_operation, status) \
         VALUES ($1, $2, 'events_telemetry_probe', $3, 'create', $4)",
    )
    .bind(subscription_ref)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .bind(status)
    .execute(db)
    .await
    .expect("insert throwaway delivery");
}

#[tokio::test]
async fn read_gauges_counts_the_backlog_per_kind_and_runs_both_lag_queries() {
    let db = skip_if_no_db!(pool().await);
    let owner = seed_owner(&db).await;
    let webhook = seed_subscription(&db, owner, "webhook").await;
    let audit = seed_subscription(&db, owner, "audit").await;

    let before = telemetry::read_gauges(&db).await.expect("read_gauges");

    seed_delivery(&db, webhook, "dead_letter").await;
    seed_delivery(&db, webhook, "failed").await;
    seed_delivery(&db, audit, "dead_letter").await;
    seed_delivery(&db, audit, "delivered").await;

    let after = telemetry::read_gauges(&db).await.expect("read_gauges");

    assert_eq!(
        after.dead_letters_for("webhook") - before.dead_letters_for("webhook"),
        1
    );
    assert_eq!(
        after.retrying_for("webhook") - before.retrying_for("webhook"),
        1
    );
    assert_eq!(
        after.dead_letters_for("audit") - before.dead_letters_for("audit"),
        1
    );
    assert_eq!(
        after.retrying_for("audit"),
        before.retrying_for("audit"),
        "a delivered row is not backlog"
    );
    for kind in ["webhook", "audit"] {
        let lag = after.lag_max_for(kind);
        assert!(
            (0..=LAG_CAP).contains(&lag),
            "{kind} lag {lag} outside 0..={LAG_CAP}"
        );
    }
}
