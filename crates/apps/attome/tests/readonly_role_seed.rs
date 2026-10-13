//! Integration tests for `attome::readonly_role_seed` (D-094/D-097): the boot-time
//! step that grants LOGIN and applies `database.readonly.password` to the
//! `attome_readonly` role created NOLOGIN by migrations/0010_readonly_query_role.sql,
//! so the password never lives as a literal in checked-in SQL.
//!
//! Requires a live Postgres (`DATABASE_URL`) with migrations already applied
//! (`cargo run -p server` once against the throwaway DB, or run the migrator
//! directly) — skips (loudly) when `DATABASE_URL` is unset, except under `CI`, per the
//! attome-api P1.8 testing-baseline convention `middleware_pipeline.rs` also
//! follows. NOT wired into any CI run yet; run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test readonly_role_seed -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::readonly_role_seed;
use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;

fn test_config(readonly_password: Option<&str>) -> AppConfig {
    let readonly_block = match readonly_password {
        Some(pw) => format!(r#""readonly": {{ "user": "attome_readonly", "password": "{pw}" }},"#),
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
                {readonly_block}
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
        readonly_block = readonly_block,
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
fn require_database_url() -> Option<()> {
    attome_testkit::migrated_db_url().map(|_| ())
}

/// D-094: the role migration 0010 creates NOLOGIN must end up LOGIN-capable
/// with the configured password after `seed` runs, and must actually be able
/// to authenticate and SELECT — not just "the function returned Ok".
#[tokio::test]
async fn seed_grants_login_and_applies_the_configured_password() {
    skip_if_no_db!(require_database_url());
    let password = format!("readonly-seed-test-{}", uuid::Uuid::now_v7());
    let config = test_config(Some(&password));

    let db = attome_db::create_pool(&attome_testkit::bootstrap_identity(&config))
        .await
        .expect("connect DATABASE_URL");
    readonly_role_seed::seed(&db, &config)
        .await
        .expect("seed must succeed when database.readonly is configured");

    // Prove the role can actually authenticate with the freshly-applied
    // password — the real thing production cares about, not just that the
    // ALTER ROLE statement executed without error.
    let readonly_options = connect_options_for_role("attome_readonly", &password);
    let readonly_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(readonly_options)
        .await
        .expect("attome_readonly must authenticate with the password seed just applied");

    sqlx::query("SELECT 1")
        .execute(&readonly_pool)
        .await
        .expect("attome_readonly must be able to run a plain SELECT");

    let write_denied = sqlx::query("UPDATE sql_query SET is_report = is_report WHERE false")
        .execute(&readonly_pool)
        .await;
    assert!(
        write_denied.is_err(),
        "attome_readonly must not be able to UPDATE — SELECT-only containment boundary"
    );

    readonly_pool.close().await;
}

/// Rotation (D-094's stated design goal): re-running `seed` with a new
/// password must supersede the previous one, not merely tolerate re-running.
#[tokio::test]
async fn seed_is_idempotent_and_rotation_supersedes_the_previous_password() {
    skip_if_no_db!(require_database_url());

    let old_password = format!("readonly-seed-test-old-{}", uuid::Uuid::now_v7());
    let db = attome_db::create_pool(&test_config(Some(&old_password)))
        .await
        .expect("connect DATABASE_URL");
    readonly_role_seed::seed(&db, &test_config(Some(&old_password)))
        .await
        .expect("first seed must succeed");

    let new_password = format!("readonly-seed-test-new-{}", uuid::Uuid::now_v7());
    readonly_role_seed::seed(&db, &test_config(Some(&new_password)))
        .await
        .expect("second seed (rotation) must succeed");

    assert!(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options_for_role("attome_readonly", &old_password))
            .await
            .is_err(),
        "the superseded password must no longer authenticate"
    );

    let rotated_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_readonly", &new_password))
        .await
        .expect("the rotated password must authenticate");
    rotated_pool.close().await;
}

/// Builds connection options for a given role/password against the same
/// host/port/database `DATABASE_URL` points at, without pulling in a `url`
/// crate dependency this workspace doesn't otherwise have — `PgConnectOptions`
/// already parses `DATABASE_URL` for us, we only override the credentials.
fn connect_options_for_role(role: &str, password: &str) -> sqlx::postgres::PgConnectOptions {
    use std::str::FromStr;
    let base_url = attome_testkit::migrated_db_url().expect("checked by require_database_url");
    sqlx::postgres::PgConnectOptions::from_str(&base_url)
        .expect("DATABASE_URL must be a valid postgres:// URL")
        .username(role)
        .password(password)
}

/// When `database.readonly` is absent (local `APP_ENV=debug` without the
/// role configured), `seed` must no-op rather than error — D-038's
/// fail-closed enforcement lives in `create_readonly_pool`/`main.rs`, not here.
#[tokio::test]
async fn seed_no_ops_when_readonly_is_not_configured() {
    skip_if_no_db!(require_database_url());
    let config = test_config(None);
    let db = attome_db::create_pool(&attome_testkit::bootstrap_identity(&config))
        .await
        .expect("connect DATABASE_URL");

    readonly_role_seed::seed(&db, &config)
        .await
        .expect("seed must no-op (Ok) when database.readonly is unset, not error");
}

/// P-stored-query-containment (D-126): migration 0046 revokes attome_readonly's
/// blanket `SELECT ON ALL TABLES`/default-privileges grant (migration 0010).
/// This asserts the containment boundary the plan's definition-of-done
/// describes directly — no credential/security table is readable at all
/// (refresh_token, and the migration bookkeeping table itself), and no
/// query can read a credential-bearing entity's excluded column
/// (user_account.password_hash, api_key.secret_hash) even when it IS
/// otherwise a registered, column-level-granted entity (D-126's "wrinkle" —
/// see migration 0046's header comment for why user_account/api_key
/// aren't simply denied outright the way refresh_token is: they're
/// registered CRUD entities with their own seeded list query, D-036, so
/// query/execute needs to keep reading their non-credential columns).
///
/// Requires migrations 0046/0047 already applied, same precondition as every
/// other test in this file.
#[tokio::test]
async fn attome_readonly_cannot_read_credential_or_security_tables() {
    skip_if_no_db!(require_database_url());
    let password = format!("readonly-containment-test-{}", uuid::Uuid::now_v7());
    let config = test_config(Some(&password));

    let db = attome_db::create_pool(&attome_testkit::bootstrap_identity(&config))
        .await
        .expect("connect DATABASE_URL");
    readonly_role_seed::seed(&db, &config)
        .await
        .expect("seed must succeed when database.readonly is configured");

    let readonly_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_readonly", &password))
        .await
        .expect("attome_readonly must authenticate with the freshly-applied password");

    // Never entity-registered, never granted by anything — migration 0046
    // names nothing here. Refresh tokens are the clearest "credential table"
    // example; the migrator bookkeeping table proves the boundary covers
    // platform internals too, not just obviously-sensitive application data.
    for table in ["refresh_token", "_sqlx_migrations"] {
        let denied = sqlx::query(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&readonly_pool)
            .await;
        assert!(
            denied.is_err(),
            "attome_readonly must not be able to read {table} at all post-containment"
        );
    }

    // user_account/api_key ARE registered entities with a column-level
    // grant (the D-126 "wrinkle") — a bare count(*) may succeed depending on
    // whether the deployment has ever booted (entity_info only has rows
    // once the app's seed functions have run at least once), but reading the
    // specifically-excluded credential column must NEVER succeed regardless.
    for (table, column) in [
        ("user_account", "password_hash"),
        ("api_key", "secret_hash"),
    ] {
        let denied = sqlx::query(&format!("SELECT {column} FROM {table} LIMIT 1"))
            .fetch_optional(&readonly_pool)
            .await;
        assert!(
            denied.is_err(),
            "attome_readonly must not be able to read {table}.{column} under any circumstance"
        );
    }

    readonly_pool.close().await;
}

/// P-stored-query-containment addendum §11(b) / migration 0060: migration
/// 0046 revoked attome_readonly's blanket table-level SELECT but never
/// touched function-EXECUTE privilege, which Postgres grants to PUBLIC by
/// default (and every role, including attome_readonly, implicitly inherits
/// PUBLIC's grants) — so a function attome_readonly was never meant to call
/// was reachable regardless. `generate_ulid()` (migration 0014) is the one
/// function that happens to live in this app's own schema rather than a
/// separate one (`apalis`, `pg_catalog`), making it the direct proof that
/// migration 0060's `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA ... FROM
/// PUBLIC` actually closed that door, independent of query_admin.rs's
/// publish-time `Function Scan` lint (a friendlier error, not the
/// guarantee — same split migration 0046's own header documents for
/// tables).
///
/// Requires migration 0060 already applied, same precondition as every
/// other test in this file.
#[tokio::test]
async fn attome_readonly_cannot_execute_schema_local_functions() {
    skip_if_no_db!(require_database_url());
    let password = format!("readonly-fn-containment-test-{}", uuid::Uuid::now_v7());
    let config = test_config(Some(&password));

    let db = attome_db::create_pool(&attome_testkit::bootstrap_identity(&config))
        .await
        .expect("connect DATABASE_URL");
    readonly_role_seed::seed(&db, &config)
        .await
        .expect("seed must succeed when database.readonly is configured");

    let readonly_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_readonly", &password))
        .await
        .expect("attome_readonly must authenticate with the freshly-applied password");

    let denied = sqlx::query("SELECT generate_ulid()")
        .fetch_one(&readonly_pool)
        .await;
    assert!(
        denied.is_err(),
        "attome_readonly must not be able to EXECUTE a schema-local function post-containment"
    );

    readonly_pool.close().await;
}

/// Migration 0123: `attome_search::routes::search` runs its fused statement on
/// `AppState::read_pool`, which is the `attome_readonly` pool whenever the
/// caller has no sticky-primary pin — but 0107 created
/// `search_index` granting `attome_runtime` only, so every unpinned
/// search failed with `permission denied for table search_index`,
/// surfaced as a 500. The negative test above proves containment holds; this
/// is its positive counterpart, and the regression guard for the one table
/// whose grant the platform's own read path depends on.
///
/// A bare `count(*)` is the assertion on purpose: it needs SELECT on the
/// table and nothing else, so it fails for exactly the reason 0123 fixes and
/// not for any data-dependent one (an empty index is a passing state).
///
/// Requires migration 0123 already applied, same precondition as every other
/// test in this file.
#[tokio::test]
async fn attome_readonly_can_read_the_search_index() {
    skip_if_no_db!(require_database_url());
    let password = format!("readonly-search-index-test-{}", uuid::Uuid::now_v7());
    let config = test_config(Some(&password));

    let db = attome_db::create_pool(&attome_testkit::bootstrap_identity(&config))
        .await
        .expect("connect DATABASE_URL");
    readonly_role_seed::seed(&db, &config)
        .await
        .expect("seed must succeed when database.readonly is configured");

    let readonly_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options_for_role("attome_readonly", &password))
        .await
        .expect("attome_readonly must authenticate with the freshly-applied password");

    let allowed = sqlx::query("SELECT count(*) FROM search_index")
        .fetch_one(&readonly_pool)
        .await;
    assert!(
        allowed.is_ok(),
        "attome_readonly must be able to read search_index — the search \
         route's own read pool is this role (migration 0123); got {:?}",
        allowed.err()
    );

    readonly_pool.close().await;
}
