//! M62 Phase 1 — proves the idempotency mechanism `dispatch::dispatch_one`
//! depends on: at most one `event_delivery` row and at most one
//! eligible delivery job per `(subscription, event)` pair, even under a
//! re-read of the same outbox event (crash-and-retry, or two dispatcher
//! runs overlapping).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-events --test dedupe -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::change_feed::{ChangeEvent, ChangeOperation};
use attome_db::DbPool;
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
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("events-dedupe-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

async fn seed_subscription(db: &DbPool, owner_ref: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO event_subscription \
            (name, kind, target_url, webhook_secret_encrypted, owner_ref) \
         VALUES ($1, 'webhook', 'http://127.0.0.1:9/unreachable', 'not-a-real-ciphertext', $2) \
         RETURNING id",
    )
    .bind(format!("dedupe-test-{}", Uuid::now_v7()))
    .bind(owner_ref)
    .fetch_one(db)
    .await
    .expect("insert throwaway subscription")
}

fn fake_event(entity: &str, operation: ChangeOperation) -> ChangeEvent {
    ChangeEvent {
        id: Uuid::now_v7(),
        entity_logicalname: entity.to_string(),
        record_id: Uuid::now_v7(),
        operation: operation.as_str().to_string(),
        event_name: None,
        created_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn a_second_insert_for_the_same_subscription_and_event_is_a_no_op() {
    let db = skip_if_no_db!(pool().await);
    let owner = seed_owner(&db).await;
    let sub_id = seed_subscription(&db, owner).await;
    let event = fake_event("events_dedupe_probe", ChangeOperation::Create);

    let first = attome_events::dispatch::create_delivery_row(&db, sub_id, &event)
        .await
        .expect("first insert must succeed");
    assert!(
        first.is_some(),
        "the first insert for a new pair must create a row"
    );

    let second = attome_events::dispatch::create_delivery_row(&db, sub_id, &event)
        .await
        .expect("second insert must not error");
    assert!(
        second.is_none(),
        "a second insert for the SAME (subscription, event) pair must be a no-op \
         (migration 0144's UNIQUE (subscription_ref, event_id)), not a duplicate row"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_delivery WHERE subscription_ref = $1 AND event_id = $2",
    )
    .bind(sub_id)
    .bind(event.id)
    .fetch_one(&db)
    .await
    .expect("count delivery rows");
    assert_eq!(count, 1, "exactly one delivery row must exist for the pair");
}

#[tokio::test]
async fn different_events_for_the_same_subscription_each_get_their_own_row() {
    let db = skip_if_no_db!(pool().await);
    let owner = seed_owner(&db).await;
    let sub_id = seed_subscription(&db, owner).await;
    let event_a = fake_event("events_dedupe_probe", ChangeOperation::Create);
    let event_b = fake_event("events_dedupe_probe", ChangeOperation::Update);

    let a = attome_events::dispatch::create_delivery_row(&db, sub_id, &event_a)
        .await
        .expect("insert a");
    let b = attome_events::dispatch::create_delivery_row(&db, sub_id, &event_b)
        .await
        .expect("insert b");
    assert!(a.is_some());
    assert!(b.is_some());
    assert_ne!(a, b, "distinct events must get distinct delivery rows");
}

/// `enqueue_dedup`'s own guarantee (apalis `push_job_dedup`, migration
/// `0060`) — the second half of dispatch's idempotency story once a
/// delivery row exists: at most one eligible (Pending/Running/Failed) job
/// row per `delivery_id`.
#[tokio::test]
async fn enqueue_dedup_only_creates_one_eligible_job_per_delivery_id() {
    let db = skip_if_no_db!(pool().await);
    let owner = seed_owner(&db).await;
    let sub_id = seed_subscription(&db, owner).await;
    let event = fake_event("events_dedupe_probe", ChangeOperation::Create);
    let delivery_id = attome_events::dispatch::create_delivery_row(&db, sub_id, &event)
        .await
        .expect("insert")
        .expect("must be new");

    let dedup_key = delivery_id.to_string();
    let first = attome_jobs::enqueue_dedup(
        &db,
        attome_core::jobs::EngineJob::EventsDeliverWebhook { delivery_id },
        &dedup_key,
    )
    .await
    .expect("first enqueue must succeed");
    assert!(
        first,
        "the first enqueue for a new delivery_id must insert a row"
    );

    let second = attome_jobs::enqueue_dedup(
        &db,
        attome_core::jobs::EngineJob::EventsDeliverWebhook { delivery_id },
        &dedup_key,
    )
    .await
    .expect("second enqueue must not error");
    assert!(
        !second,
        "a second enqueue for the same delivery_id while the first job is still \
         eligible must be a no-op, not a duplicate job"
    );
}
