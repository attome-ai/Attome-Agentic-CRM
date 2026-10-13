//! BSV-F20 / A10 — `api_usage::flush` must not lose the counts it drained when
//! the upsert fails. Needs a throwaway Postgres (see `attome_testkit`) and
//! Redis/Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT`:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-server --test api_usage -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::api_usage::{self, HASH_KEY, Identity, STAGING_KEY};
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use fred::interfaces::{ClientLike, HashesInterface, KeysInterface};
use fred::prelude::*;
use uuid::Uuid;

async fn redis_pool() -> RedisPool {
    let host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("TEST_REDIS_PORT")
        .unwrap_or_else(|_| "6379".into())
        .parse()
        .expect("TEST_REDIS_PORT must be a valid port number");
    let config = RedisConfig::from_url(&format!("redis://{host}:{port}"))
        .expect("build redis config from test host/port");
    let pool = RedisPool::new(config, None, None, None, 2).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to local test Redis/Dragonfly");
    pool
}

async fn stored_count(db: &sqlx::PgPool, route: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT request_count FROM api_usage WHERE route_template = $1")
        .bind(route)
        .fetch_optional(db)
        .await
        .expect("read api_usage")
}

#[tokio::test]
async fn a_failed_rollup_insert_keeps_the_counts() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(2).await);
    let redis = redis_pool().await;
    let _: i64 = redis
        .del(vec![HASH_KEY, STAGING_KEY])
        .await
        .expect("clear keys");

    let route = format!("/api/v1/a10-{}", Uuid::now_v7());
    let today = Utc::now().date_naive();
    let who = Identity::User(Uuid::now_v7());
    for _ in 0..3 {
        api_usage::record(&redis, today, "GET", &route, &who)
            .await
            .expect("record");
    }

    let dead = attome_testkit::migrated_pool(1).await.expect("second pool");
    dead.close().await;
    assert!(
        api_usage::flush(&dead, &redis).await.is_err(),
        "a flush against a closed pool must fail"
    );

    let staged: Vec<(String, String)> = redis
        .hgetall::<std::collections::HashMap<String, String>, _>(STAGING_KEY)
        .await
        .expect("read staging hash")
        .into_iter()
        .filter(|(field, _)| field.contains(&route))
        .collect();
    assert_eq!(
        staged.len(),
        1,
        "the drained counts must survive a failed insert"
    );
    assert_eq!(staged[0].1, "3");

    for _ in 0..2 {
        api_usage::record(&redis, today, "GET", &route, &who)
            .await
            .expect("record");
    }
    let flushed = api_usage::flush(&db, &redis).await.expect("flush");
    assert!(flushed >= 2, "the leftover and the new claim both flush");
    assert_eq!(stored_count(&db, &route).await, Some(5));

    let staging_left: bool = redis.exists(STAGING_KEY).await.expect("exists");
    assert!(!staging_left, "a committed flush releases its staging hash");
    api_usage::flush(&db, &redis).await.expect("idle flush");
    assert_eq!(
        stored_count(&db, &route).await,
        Some(5),
        "nothing is double-counted by a second run"
    );
}
