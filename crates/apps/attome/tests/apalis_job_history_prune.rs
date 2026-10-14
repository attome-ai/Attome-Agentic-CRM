//! P-job-queue-hardening (D-165) — `attome::jobs::prune_apalis_job_history`
//! deletes terminal `apalis.jobs` rows past their retention, and only those:
//! `Done` past `jobs.history_retention_days`, `Killed` (dead letters) past
//! `jobs.dead_letter_retention_days` (BJB-15). It also scrubs the payload of
//! `Done` rows past a day while keeping the variant tag (BJB-11).
//!
//! Requires a live Postgres (`DATABASE_URL`) with migrations already applied
//! (0014_apalis_jobs.sql, 0060_apalis_job_dedup.sql) — panics with a clear
//! message if unset, same convention as `db_role_seed.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test apalis_job_history_prune -- --test-threads=1
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
        "jobs": { "history_retention_days": 7, "dead_letter_retention_days": 30 }
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

#[tokio::test]
async fn prune_deletes_only_terminal_rows_past_retention() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config();
    assert_eq!(config.jobs.history_retention_days, 7);
    assert_eq!(config.jobs.dead_letter_retention_days, 30);

    let old_done = format!("prune-test-old-done-{}", Uuid::now_v7());
    let old_killed = format!("prune-test-old-killed-{}", Uuid::now_v7());
    let young_killed = format!("prune-test-young-killed-{}", Uuid::now_v7());
    let recent_done = format!("prune-test-recent-done-{}", Uuid::now_v7());
    let old_but_pending = format!("prune-test-old-pending-{}", Uuid::now_v7());
    let old_but_failed = format!("prune-test-old-failed-{}", Uuid::now_v7());

    sqlx::query(
        "INSERT INTO apalis.jobs (job, id, job_type, status, done_at, run_at) VALUES
             ('\"EnsureAuditPartitions\"', $1, 'platform_job', 'Done',   now() - interval '10 days', now() - interval '10 days'),
             ('\"EnsureAuditPartitions\"', $2, 'platform_job', 'Killed', now() - interval '40 days', now() - interval '40 days'),
             ('\"EnsureAuditPartitions\"', $6, 'platform_job', 'Killed', now() - interval '10 days', now() - interval '10 days'),
             ('\"EnsureAuditPartitions\"', $3, 'platform_job', 'Done',   now() - interval '1 hour',  now() - interval '1 hour'),
             ('\"EnsureAuditPartitions\"', $4, 'platform_job', 'Pending', NULL, now() - interval '10 days'),
             ('\"EnsureAuditPartitions\"', $5, 'platform_job', 'Failed', NULL, now() - interval '10 days')",
    )
    .bind(&old_done)
    .bind(&old_killed)
    .bind(&recent_done)
    .bind(&old_but_pending)
    .bind(&old_but_failed)
    .bind(&young_killed)
    .execute(&db)
    .await
    .expect("seed apalis.jobs rows");

    attome::jobs::prune_apalis_job_history(&db, &config)
        .await
        .expect("prune_apalis_job_history");

    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT id FROM apalis.jobs WHERE id = ANY($1)")
            .bind([
                old_done.clone(),
                old_killed.clone(),
                recent_done.clone(),
                old_but_pending.clone(),
                old_but_failed.clone(),
                young_killed.clone(),
            ])
            .fetch_all(&db)
            .await
            .expect("query remaining rows");

    assert!(
        !remaining.contains(&old_done),
        "an old Done row past retention must be deleted"
    );
    assert!(
        !remaining.contains(&old_killed),
        "a Killed (dead-letter) row past dead_letter_retention_days must be deleted"
    );
    assert!(
        remaining.contains(&young_killed),
        "a Killed row past history retention but inside dead_letter_retention_days must          survive (BJB-15: dead letters follow their own, longer retention)"
    );
    assert!(
        remaining.contains(&recent_done),
        "a recent Done row within retention must survive"
    );
    assert!(
        remaining.contains(&old_but_pending),
        "a Pending row must never be pruned regardless of age -- it isn't terminal"
    );
    assert!(
        remaining.contains(&old_but_failed),
        "a still-retrying Failed row must never be pruned regardless of age -- it isn't terminal"
    );
}

/// BJB-11 — a `Done` row past the scrub window loses its payload but keeps its
/// variant (so the admin list still names it); a `Killed` row keeps its
/// payload, because a dead letter may still be replayed.
#[tokio::test]
async fn prune_scrubs_done_payloads_and_keeps_dead_letter_payloads() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config();

    let done = format!("prune-test-scrub-done-{}", Uuid::now_v7());
    let killed = format!("prune-test-scrub-killed-{}", Uuid::now_v7());
    let envelope = serde_json::json!({
        "version": 1,
        "variant": "BulkEntityOperation",
        "payload": { "bulk_op_id": "00000000-0000-0000-0000-000000000000" },
        "trace_context": null
    });

    sqlx::query(
        "INSERT INTO apalis.jobs (job, id, job_type, status, done_at, run_at) VALUES
             ($1, $2, 'platform_job_batch', 'Done',   now() - interval '2 days', now() - interval '2 days'),
             ($1, $3, 'platform_job_batch', 'Killed', now() - interval '2 days', now() - interval '2 days')",
    )
    .bind(&envelope)
    .bind(&done)
    .bind(&killed)
    .execute(&db)
    .await
    .expect("seed apalis.jobs rows");

    attome::jobs::prune_apalis_job_history(&db, &config)
        .await
        .expect("prune_apalis_job_history");

    let job_of = |id: String| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, serde_json::Value>("SELECT job FROM apalis.jobs WHERE id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .expect("the row is still there")
        }
    };

    let scrubbed = job_of(done.clone()).await;
    assert!(
        scrubbed["payload"].is_null(),
        "a Done row's payload is scrubbed: {scrubbed}"
    );
    assert_eq!(
        scrubbed["scrubbed"], true,
        "the scrub marks the row: {scrubbed}"
    );
    assert_eq!(
        attome_jobs::job_variant_tag(&scrubbed),
        Some("BulkEntityOperation"),
        "the variant tag survives the scrub"
    );

    let kept = job_of(killed).await;
    assert_eq!(kept, envelope, "a dead letter keeps its payload for replay");

    // Idempotent: a second sweep leaves the scrubbed row as it was.
    attome::jobs::prune_apalis_job_history(&db, &config)
        .await
        .expect("second prune");
    assert_eq!(job_of(done).await, scrubbed);
}

/// BJB-15 — the hard delete runs in bounded batches (5 000 rows each) until a
/// batch comes back short, so 12 000 expired rows go in one run.
#[tokio::test]
async fn prune_deletes_a_large_backlog_in_batches() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config();
    let prefix = format!("prune-test-batch-{}-", Uuid::now_v7());

    // Seeded in chunks: one 12 000-row statement outlives the pool's
    // statement_timeout on a loaded dev box.
    for chunk in 0..6 {
        sqlx::query(
            "INSERT INTO apalis.jobs (job, id, job_type, status, done_at, run_at)
             SELECT '\"EnsureAuditPartitions\"', $1 || n, 'platform_job', 'Done',
                    now() - interval '10 days', now() - interval '10 days'
             FROM generate_series($2 * 2000 + 1, $2 * 2000 + 2000) AS n",
        )
        .bind(&prefix)
        .bind(chunk)
        .execute(&db)
        .await
        .expect("seed 12 000 expired Done rows");
    }

    attome::jobs::prune_apalis_job_history(&db, &config)
        .await
        .expect("prune_apalis_job_history");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM apalis.jobs WHERE id LIKE $1 || '%'")
        .bind(&prefix)
        .fetch_one(&db)
        .await
        .expect("count remaining rows");
    assert_eq!(
        left, 0,
        "all 12 000 expired rows are deleted across batches"
    );
}
