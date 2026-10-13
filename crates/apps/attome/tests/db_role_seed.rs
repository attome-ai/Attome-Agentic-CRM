//! Integration tests for `attome::db_role_seed` (D-117): the boot-time step
//! that grants LOGIN and applies `database.migrator`/`database.runtime`'s
//! configured password to the `attome_migrator` (DDL) and `attome_runtime`
//! (DML-only) roles created NOLOGIN by migrations/0042_migrator_runtime_roles.sql,
//! mirroring `readonly_role_seed.rs`'s D-094/D-097 pattern for the two new
//! roles D-117 added.
//!
//! Requires a live Postgres (`DATABASE_URL`) with migrations already applied
//! (`cargo run -p server` once against the throwaway DB, or run the migrator
//! directly) — skips (loudly) when `DATABASE_URL` is unset, except under `CI`, per the
//! attome-api P1.8 testing-baseline convention `readonly_role_seed.rs` also
//! follows. NOT wired into any CI run yet; run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test db_role_seed -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::db_role_seed;
use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;

fn test_config(migrator_password: Option<&str>, runtime_password: Option<&str>) -> AppConfig {
    let migrator_block = match migrator_password {
        Some(pw) => format!(r#""migrator": {{ "user": "attome_migrator", "password": "{pw}" }},"#),
        None => String::new(),
    };
    let runtime_block = match runtime_password {
        Some(pw) => format!(r#""runtime": {{ "user": "attome_runtime", "password": "{pw}" }},"#),
        None => String::new(),
    };

    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1024, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                {migrator_block}
                {runtime_block}
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "localhost", "port": 6379, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}}
            }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["http://allowed.test"] }}
        }}"#,
        migrator_block = migrator_block,
        runtime_block = runtime_block,
    );

    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
fn require_database_url() -> Option<()> {
    attome_testkit::migrated_db_url().map(|_| ())
}

fn connect_options_for_role(role: &str, password: &str) -> sqlx::postgres::PgConnectOptions {
    use std::str::FromStr;
    let base_url = attome_testkit::migrated_db_url().expect("checked by require_database_url");
    sqlx::postgres::PgConnectOptions::from_str(&base_url)
        .expect("DATABASE_URL must be a valid postgres:// URL")
        .username(role)
        .password(password)
}

/// D-117: `attome_migrator`, created NOLOGIN by migration 0042, must end up
/// LOGIN-capable with the configured password after `seed_migrator` runs —
/// and must actually be able to authenticate and run DDL (the containment
/// boundary this role exists for), not just DML.
#[tokio::test]
async fn seed_migrator_grants_login_and_can_run_ddl() {
    skip_if_no_db!(require_database_url());
    let password = format!("migrator-seed-test-{}", uuid::Uuid::now_v7());
    let config = test_config(Some(&password), None);

    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    db_role_seed::seed_migrator(&db, &config)
        .await
        .expect("seed_migrator must succeed when database.migrator is configured");

    let migrator_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_migrator", &password))
        .await
        .expect("attome_migrator must authenticate with the password seed just applied");

    let table_name = format!("db_role_seed_test_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE TABLE {table_name} (id uuid PRIMARY KEY)"))
        .execute(&migrator_pool)
        .await
        .expect("attome_migrator must be able to CREATE TABLE — DDL is its whole purpose");

    sqlx::query(&format!("DROP TABLE {table_name}"))
        .execute(&migrator_pool)
        .await
        .expect("attome_migrator must be able to DROP its own table");

    migrator_pool.close().await;
}

/// D-117: `attome_runtime`, created NOLOGIN by migration 0042, must end up
/// LOGIN-capable with the configured password after `seed_runtime` runs, be
/// able to do ordinary DML, but must NOT be able to run DDL — that's the
/// entire containment boundary this role exists for.
#[tokio::test]
async fn seed_runtime_grants_login_can_dml_but_not_ddl() {
    skip_if_no_db!(require_database_url());
    let password = format!("runtime-seed-test-{}", uuid::Uuid::now_v7());
    let config = test_config(None, Some(&password));

    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    db_role_seed::seed_runtime(&db, &config)
        .await
        .expect("seed_runtime must succeed when database.runtime is configured");

    let runtime_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_runtime", &password))
        .await
        .expect("attome_runtime must authenticate with the password seed just applied");

    sqlx::query("SELECT 1")
        .execute(&runtime_pool)
        .await
        .expect("attome_runtime must be able to run a plain SELECT");

    let ddl_denied = sqlx::query("CREATE TABLE db_role_seed_should_never_exist (id uuid)")
        .execute(&runtime_pool)
        .await;
    assert!(
        ddl_denied.is_err(),
        "attome_runtime must not be able to CREATE TABLE — DML-only containment boundary"
    );

    runtime_pool.close().await;
}

/// D-117/D-148 follow-up, migration 0072: `attome_runtime` keeps ordinary DML
/// everywhere, but must NOT be able to UPDATE or DELETE the append-only
/// audit ledger / license registry tables, must NOT be able to UPDATE the
/// audit ingest staging table, and must NOT be able to DELETE the erasure
/// key registry — the DB-level backstop behind the entity engine's
/// `is_append_only` flag. Permission is checked before row-matching, so no
/// seed data is needed for these statements to fail.
///
/// Live-verified against a real Postgres (2026-08-03): passes against
/// migrations 0003/0006/0016/0039/0048's current column names.
#[tokio::test]
async fn seed_runtime_cannot_mutate_append_only_audit_and_license_tables() {
    skip_if_no_db!(require_database_url());
    let password = format!("runtime-seed-test-{}", uuid::Uuid::now_v7());
    let config = test_config(None, Some(&password));

    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    db_role_seed::seed_runtime(&db, &config)
        .await
        .expect("seed_runtime must succeed when database.runtime is configured");

    let runtime_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_runtime", &password))
        .await
        .expect("attome_runtime must authenticate with the password seed just applied");

    let nil = uuid::Uuid::nil();

    for (sql, table) in [
        (
            "UPDATE audit_header SET event_hash = 'x' WHERE id = $1",
            "audit_header",
        ),
        ("DELETE FROM audit_header WHERE id = $1", "audit_header"),
        (
            "UPDATE audit_detail SET field_name = 'x' WHERE id = $1",
            "audit_detail",
        ),
        (
            "UPDATE audit_snapshot SET is_active = FALSE WHERE id = $1",
            "audit_snapshot",
        ),
        (
            "UPDATE audit_chain_batch SET merkle_root = 'x' WHERE id = $1",
            "audit_chain_batch",
        ),
        (
            "UPDATE audit_signing_key SET public_key = 'x' WHERE key_id = $1::text",
            "audit_signing_key",
        ),
        ("UPDATE license SET domain = 'x' WHERE id = $1", "license"),
        (
            "UPDATE audit_ingest SET created_at = NOW() WHERE id = $1",
            "audit_ingest",
        ),
        (
            "DELETE FROM audit_erasure_key WHERE record_id = $1",
            "audit_erasure_key",
        ),
    ] {
        let result = sqlx::query(sql).bind(nil).execute(&runtime_pool).await;
        assert!(
            result.is_err(),
            "attome_runtime must not be able to run `{sql}` against {table} — \
             migration 0072's containment boundary"
        );
    }

    runtime_pool.close().await;
}

/// Rotation (same D-094 design goal as `attome_readonly`): re-running
/// `seed_migrator`/`seed_runtime` with a new password must supersede the
/// previous one, not merely tolerate re-running.
#[tokio::test]
async fn seed_is_idempotent_and_rotation_supersedes_the_previous_password() {
    skip_if_no_db!(require_database_url());

    let old_password = format!("migrator-seed-test-old-{}", uuid::Uuid::now_v7());
    let db = attome_db::create_pool(&test_config(Some(&old_password), None))
        .await
        .expect("connect DATABASE_URL");
    db_role_seed::seed_migrator(&db, &test_config(Some(&old_password), None))
        .await
        .expect("first seed must succeed");

    let new_password = format!("migrator-seed-test-new-{}", uuid::Uuid::now_v7());
    db_role_seed::seed_migrator(&db, &test_config(Some(&new_password), None))
        .await
        .expect("second seed (rotation) must succeed");

    assert!(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options_for_role("attome_migrator", &old_password))
            .await
            .is_err(),
        "the superseded password must no longer authenticate"
    );

    let rotated_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_migrator", &new_password))
        .await
        .expect("the rotated password must authenticate");
    rotated_pool.close().await;
}

/// When `database.migrator`/`database.runtime` are absent (local
/// `APP_ENV=debug` without either role configured), both seed functions must
/// no-op rather than error — same posture as `readonly_role_seed::seed`.
#[tokio::test]
async fn seed_no_ops_when_migrator_and_runtime_are_not_configured() {
    skip_if_no_db!(require_database_url());
    let config = test_config(None, None);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");

    db_role_seed::seed_migrator(&db, &config)
        .await
        .expect("seed_migrator must no-op (Ok) when database.migrator is unset, not error");
    db_role_seed::seed_runtime(&db, &config)
        .await
        .expect("seed_runtime must no-op (Ok) when database.runtime is unset, not error");
}
