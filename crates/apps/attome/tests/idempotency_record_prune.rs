//! D-207 follow-up — `attome::jobs::prune_idempotency_records` soft-deletes
//! `idempotency_record` rows past `idempotency.durable_retention_hours`,
//! regardless of `state` ('pending' or 'completed' — the SQL has no `state`
//! filter, matching `crates/server/src/jobs.rs::prune_idempotency_records`'s
//! own body). This is the long-horizon retention/cleanup sweep; a *recently*
//! orphaned `pending` row (a crashed request) is instead recovered by
//! `attome_server::middleware::idempotency_durable`'s stale-pending reclaim —
//! this test only proves the retention job's own behavior, not that
//! mechanism (see `attome-server/tests/idempotency_durable.rs`).
//!
//! Requires a live Postgres (`DATABASE_URL`) with migrations already applied
//! (`0066_core_idempotency_record.sql`) — skips (loudly) when it is
//! unset, except under `CI` (see `attome_testkit`), same convention as
//! `apalis_job_history_prune.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test idempotency_record_prune -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
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
        "idempotency": { "durable_retention_hours": 24 }
    }"#;
    attome_testkit::with_test_database(serde_json::from_str(json).expect("test_config JSON must deserialize into AppConfig"), true)
}

/// The throwaway clone with the platform schema on the search path: the
/// debug `DATABASE_URL` override reaches the clone but not `database.schema`.
async fn test_pool() -> Option<attome_db::DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO attome_dev, public")
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

/// `idempotency_record.principal_ref` has a real FK to
/// `user_account` — seed a throwaway user row so the seeded records below
/// don't trip the constraint. Duplicated from
/// `attome-server/tests/idempotency_durable.rs`'s own helper rather than
/// shared cross-crate, same convention `boot.rs`'s test fixtures already use
/// for a single test-only shape.
async fn seed_throwaway_user(db: &attome_db::DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, is_active, created_at) VALUES ($1, $2, true, now())",
    )
    .bind(id)
    .bind(format!("idempotency-prune-test-{id}@drill.local"))
    .execute(db)
    .await
    .expect("seed throwaway user_account row");
    id
}

#[tokio::test]
async fn prune_soft_deletes_rows_past_retention_regardless_of_state() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config();
    assert_eq!(config.idempotency.durable_retention_hours, 24);

    let user = seed_throwaway_user(&db).await;

    let old_completed = Uuid::now_v7();
    let old_but_never_completed = Uuid::now_v7();
    let recent_completed = Uuid::now_v7();

    sqlx::query(
        "INSERT INTO idempotency_record
            (id, principal_ref, http_method, operation, client_key, body_hash, state,
             created_at, updated_at)
         VALUES
            ($1, $4, 'POST', 'op-prune-test', 'key-old-completed', 'hash', 'completed',
             now() - interval '48 hours', now() - interval '48 hours'),
            ($2, $4, 'POST', 'op-prune-test', 'key-old-pending', 'hash', 'pending',
             now() - interval '48 hours', now() - interval '48 hours'),
            ($3, $4, 'POST', 'op-prune-test', 'key-recent', 'hash', 'completed',
             now() - interval '1 hour', now() - interval '1 hour')",
    )
    .bind(old_completed)
    .bind(old_but_never_completed)
    .bind(recent_completed)
    .bind(user)
    .execute(&db)
    .await
    .expect("seed idempotency_record rows");

    attome::jobs::prune_idempotency_records(&db, &config)
        .await
        .expect("prune_idempotency_records");

    let rows: Vec<(Uuid, bool)> =
        sqlx::query_as("SELECT id, is_deleted FROM idempotency_record WHERE id = ANY($1)")
            .bind([old_completed, old_but_never_completed, recent_completed])
            .fetch_all(&db)
            .await
            .expect("query rows back");

    let is_deleted = |id: Uuid| {
        rows.iter()
            .find(|(row_id, _)| *row_id == id)
            .map(|(_, deleted)| *deleted)
            .unwrap_or_else(|| {
                panic!("row {id} disappeared entirely — prune must soft-delete, never hard-delete")
            })
    };

    assert!(
        is_deleted(old_completed),
        "an old completed row past retention must be soft-deleted"
    );
    assert!(
        is_deleted(old_but_never_completed),
        "an old, never-completed/never-retried pending row past retention must also be \
         soft-deleted — prune_idempotency_records doesn't discriminate by state, and by this \
         point any legitimate retry had a 48-hour window to reclaim it instead"
    );
    assert!(
        !is_deleted(recent_completed),
        "a recent row within retention must survive"
    );
}

/// attome-server plan B2 / BSV-D1 — the second window: a row swept more than
/// `IDEMPOTENCY_HARD_DELETE_AFTER_DAYS` ago is removed outright; one swept
/// recently stays soft-deleted for traceability.
#[tokio::test]
async fn prune_hard_deletes_rows_swept_past_the_second_window() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config();
    let user = seed_throwaway_user(&db).await;

    let swept_long_ago = Uuid::now_v7();
    let swept_recently = Uuid::now_v7();
    let days = attome::jobs::IDEMPOTENCY_HARD_DELETE_AFTER_DAYS;

    sqlx::query(
        "INSERT INTO idempotency_record
            (id, principal_ref, http_method, operation, client_key, body_hash, state,
             is_deleted, created_at, updated_at)
         VALUES
            ($1, $3, 'POST', 'op-prune-test', 'key-swept-old', 'hash', 'completed', TRUE,
             now() - make_interval(days => $4 + 2), now() - make_interval(days => $4 + 1)),
            ($2, $3, 'POST', 'op-prune-test', 'key-swept-new', 'hash', 'completed', TRUE,
             now() - interval '3 days', now() - interval '1 day')",
    )
    .bind(swept_long_ago)
    .bind(swept_recently)
    .bind(user)
    .bind(days)
    .execute(&db)
    .await
    .expect("seed swept idempotency_record rows");

    attome::jobs::prune_idempotency_records(&db, &config)
        .await
        .expect("prune_idempotency_records");

    let remaining: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM idempotency_record WHERE id = ANY($1)")
            .bind([swept_long_ago, swept_recently])
            .fetch_all(&db)
            .await
            .expect("query rows back");

    assert!(
        !remaining.contains(&swept_long_ago),
        "a row swept more than {days} days ago must be hard-deleted"
    );
    assert!(
        remaining.contains(&swept_recently),
        "a recently swept row must stay (soft-deleted) until the second window passes"
    );
}
