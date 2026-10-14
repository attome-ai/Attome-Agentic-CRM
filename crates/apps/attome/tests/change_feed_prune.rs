//! M01 §7 C-04 — `attome::jobs::prune_change_feed` deletes
//! `entity_change_event` rows every registered consumer cursor has
//! passed and that are older than `change_feed.retention_days`, and never an
//! event a registered cursor has not passed, however old or however
//! "processed" it is (`attome_core::change_feed::prune`'s own invariant —
//! see `attome-core/tests/change_feed.rs::prune_respects_the_slowest_cursor`
//! for that property proved directly against the library function). This
//! test proves the *job* wrapper: it derives the retention floor from
//! `change_feed.retention_days` and drives a real `entity_change_event`
//! + `change_consumer_cursor` pair end to end.
//!
//! Cursor state is set directly by SQL rather than through
//! `change_feed::read_batch`/`advance`, to avoid this test's outcome
//! depending on `pg_snapshot_xmin`'s cluster-wide visibility horizon (which
//! any concurrently-running test binary's open transaction can hold back) —
//! a legitimate "test against a throwaway database" case (guidelines §4's
//! API-first exemption list).
//!
//! Requires a live Postgres (`DATABASE_URL`) with migrations already applied
//! (`0091`, `0104`, `0105`) — skips (loudly) when unset, except under `CI`,
//! same convention as `idempotency_record_prune.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test change_feed_prune -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_config::AppConfig;
use attome_core::change_feed::{self, ChangeOperation};
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

fn test_config() -> AppConfig {
    let json = r#"{
        "app": {
            "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
            "frontend_port": 4200, "log_level": "error", "threads": 1,
            "max_body_size_bytes": 1024, "request_timeout_secs": 5,
            "enable_session": true, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "use_gzip": false,
            "enable_compression": false, "gzip_level": 1, "br_level": 1,
            "idle_connection_timeout": 30, "keepalive_requests": 100,
            "static_files_cache_time": 0, "server_header_field": "attome-test"
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
            "user": "unused", "password": "unused", "schema": "attome_dev",
            "connection_number": 5, "timeout": 5.0
        },
        "cache": {
            "host": "localhost", "port": 6379, "password": "",
            "db": 0, "connection_pool_size": 4, "timeout": 2000,
            "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": false
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
            "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
            "oauth_google_client_id": "", "oauth_google_client_secret": ""
        },
        "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {} },
        "observability": {
            "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "test@test.local",
            "smtp_from_name": "test", "smtp_use_tls": false,
            "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
        },
        "google_ai": {
            "api_key": "", "base_url": "https://example.invalid",
            "default_model": "none", "timeout_seconds": 1
        },
        "llm_api": {},
        "external_api": {},
        "s2s": { "enabled": false },
        "security": { "bootstrap_admin_email": null },
        "change_feed": { "retention_days": 30 }
    }"#;
    attome_testkit::with_test_database(
        serde_json::from_str(json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn test_pool() -> Option<attome_db::DbPool> {
    attome_testkit::migrated_db_url()?;
    Some(
        attome_db::create_pool(&test_config())
            .await
            .expect("connect DATABASE_URL"),
    )
}

/// Emits one change-feed row in its own committed transaction, then reports
/// back the row's own `id` and `commit_xid` (as `bigint`, matching
/// `change_feed::cursor`'s own cast) so the test can position a consumer
/// cursor relative to it without going through `read_batch`'s visibility-
/// horizon wait.
async fn emit_and_locate(db: &attome_db::DbPool, entity: &str, record_id: Uuid) -> (Uuid, i64) {
    let mut tx = db.begin().await.expect("begin");
    change_feed::emit(&mut tx, entity, record_id, ChangeOperation::Create)
        .await
        .expect("emit must succeed");
    tx.commit().await.expect("commit");

    sqlx::query_as(
        "SELECT id, commit_xid::text::bigint FROM entity_change_event \
          WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("locate the just-emitted row")
}

/// Directly upserts `consumer`'s cursor to `last_commit_xid`, bypassing
/// `change_feed::advance` (which requires an already-visible event row to
/// advance past) — a test fixture, not production behavior.
async fn set_cursor(db: &attome_db::DbPool, consumer: &str, last_commit_xid: i64) {
    sqlx::query(
        "INSERT INTO change_consumer_cursor (consumer, last_commit_xid) \
         VALUES ($1, $2::text::xid8) \
         ON CONFLICT (consumer) DO UPDATE SET last_commit_xid = EXCLUDED.last_commit_xid",
    )
    .bind(consumer)
    .bind(last_commit_xid)
    .execute(db)
    .await
    .expect("set consumer cursor");
}

/// Marks a row `processed_at` and backdates `created_at` well past any
/// plausible retention floor — the two conditions `prune` additionally
/// requires before the slowest-cursor check even matters.
async fn mark_processed_and_age(db: &attome_db::DbPool, event_id: Uuid) {
    sqlx::query(
        "UPDATE entity_change_event \
            SET processed_at = NOW(), created_at = NOW() - INTERVAL '90 days' \
          WHERE id = $1",
    )
    .bind(event_id)
    .execute(db)
    .await
    .expect("mark processed and age the row");
}

/// Marks a row `processed_at` but leaves `created_at` at its (recent)
/// insert-time default — processed and passed by every cursor, but still
/// inside the retention floor.
async fn mark_processed_only(db: &attome_db::DbPool, event_id: Uuid) {
    sqlx::query("UPDATE entity_change_event SET processed_at = NOW() WHERE id = $1")
        .bind(event_id)
        .execute(db)
        .await
        .expect("mark processed");
}

async fn row_exists(db: &attome_db::DbPool, event_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM entity_change_event WHERE id = $1)")
        .bind(event_id)
        .fetch_one(db)
        .await
        .expect("check row existence")
}

#[tokio::test]
async fn prune_change_feed_deletes_only_events_every_cursor_has_passed_and_past_retention() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config();
    assert_eq!(config.change_feed.retention_days, 30);

    let entity = format!("test_feed_job_{}", Uuid::now_v7().simple());
    let consumer = format!("test/change-feed-prune-job-{}", Uuid::now_v7());

    // Emitted first (lowest commit_xid): processed, aged past the 30-day
    // retention floor, and behind the cursor below -- eligible on every
    // count.
    let (old_and_passed_id, old_and_passed_xid) =
        emit_and_locate(&db, &entity, Uuid::now_v7()).await;

    // Emitted second, still behind the cursor below, but processed and left
    // at its recent insert-time `created_at` -- proves the config-derived
    // retention floor, not just the cursor check, gates deletion.
    let (recent_but_passed_id, recent_but_passed_xid) =
        emit_and_locate(&db, &entity, Uuid::now_v7()).await;

    // The registered consumer sits here: at/after both events above, and
    // (asserted below) strictly before the third.
    set_cursor(&db, &consumer, recent_but_passed_xid).await;

    // Emitted third (highest commit_xid) -- no consumer has read this far,
    // so it must survive regardless of age/processed state.
    let (unpassed_id, unpassed_xid) = emit_and_locate(&db, &entity, Uuid::now_v7()).await;
    assert!(
        unpassed_xid > recent_but_passed_xid && recent_but_passed_xid > old_and_passed_xid,
        "each successive emit must commit at a strictly later transaction id than the last, or \
         this test's premise (the cursor sits between event two and event three) does not hold"
    );

    mark_processed_and_age(&db, old_and_passed_id).await;
    mark_processed_only(&db, recent_but_passed_id).await;
    // Also processed+aged, to prove the cursor -- not age or processed_at
    // state -- is what protects it.
    mark_processed_and_age(&db, unpassed_id).await;

    attome::jobs::prune_change_feed(&db, &config)
        .await
        .expect("prune_change_feed");

    assert!(
        !row_exists(&db, old_and_passed_id).await,
        "an event behind every registered cursor and past the retention floor must be deleted"
    );
    assert!(
        row_exists(&db, recent_but_passed_id).await,
        "an event behind every registered cursor but still within the retention floor must \
         survive -- proves the job derives the floor from config rather than deleting \
         everything a cursor has passed"
    );
    assert!(
        row_exists(&db, unpassed_id).await,
        "an event no registered cursor has passed must survive prune regardless of age or \
         processed_at state"
    );
}
