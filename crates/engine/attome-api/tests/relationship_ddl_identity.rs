//! Relationship join-table DDL runs as the provisioning identity (D-117).
//!
//! `reconcile_relationship` created `mm_*` tables on `state.base.db`.
//! Wherever the database roles are split — required outside
//! `APP_ENV=debug` — that pool connects as `attome_runtime`, a DML-only role
//! with `USAGE` but no `CREATE` on the schema (migration 0042), so every
//! relationship create failed with `permission denied for schema`. That
//! crash-looped server boot in staging-smoke run 34822488459, while bundle
//! apply's entity and attribute steps already provision through
//! `db_migrator`.
//!
//! Every other suite builds `AppState` with `db_migrator = db.clone()`, so the
//! two identities are the same and this could never show up there. These
//! tests give the pools genuinely different roles: each connection runs
//! `SET ROLE` right after connecting, so Postgres checks privileges (and
//! assigns table ownership) as that role.
//!
//! Requires a migrated test database (`DATABASE_URL`, cloned per binary by
//! attome-testkit) and Redis (`TEST_REDIS_HOST` / `TEST_REDIS_PORT`):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test relationship_ddl_identity
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_core::{EngineState, RelationshipCascade};
use attome_metadata::provision::{
    EntityDesc, ReconcileOutcome, ReconcilePolicy, RelationshipDesc, reconcile_entity,
    reconcile_relationship,
};
use attome_server::AppState;
use attome_testkit::{skip_if_no_db, unique_logicalname};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// Insufficient privilege.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
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
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// A pool whose every connection acts as `role` for privilege checks and
/// object ownership, connected through the test database's superuser.
async fn role_pool(url: &str, role: &'static str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                let set_role = format!("SET ROLE {role}");
                sqlx::query(&set_role).execute(conn).await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap_or_else(|e| panic!("connect to the test database as {role}: {e}"))
}

/// `EngineState` with the split the production roles have: `db` is
/// `attome_runtime`, `db_migrator` is `attome_migrator`.
async fn split_role_state(url: &str) -> (EngineState, PgPool, PgPool) {
    // AppError::Internal masks its cause in Display; the real database error
    // is only visible through tracing.
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let config = test_config();
    let runtime = role_pool(url, "attome_runtime").await;
    let migrator = role_pool(url, "attome_migrator").await;
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis (TEST_REDIS_HOST / TEST_REDIS_PORT)");
    let redis_coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build storage client");
    let base = AppState::new(
        config,
        runtime.clone(),
        runtime.clone(),
        migrator.clone(),
        redis,
        redis_coordination,
        storage,
    );
    (EngineState::new(base), runtime, migrator)
}

#[tokio::test]
async fn runtime_role_cannot_create_tables_but_migrator_role_can() {
    let url = skip_if_no_db!(attome_testkit::migrated_db_url());
    let runtime = role_pool(&url, "attome_runtime").await;
    let migrator = role_pool(&url, "attome_migrator").await;

    for (pool, expected) in [(&runtime, "attome_runtime"), (&migrator, "attome_migrator")] {
        let current: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(pool)
            .await
            .expect("read current_user");
        assert_eq!(
            current, expected,
            "SET ROLE must take effect on every pooled connection"
        );
    }

    let table = unique_logicalname("ddl_identity_probe");
    let create = format!(r#"CREATE TABLE "{table}" (id uuid PRIMARY KEY)"#);

    let denied = sqlx::query(&create)
        .execute(&runtime)
        .await
        .expect_err("attome_runtime must not be able to CREATE TABLE in the schema");
    let code = denied
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some(SQLSTATE_INSUFFICIENT_PRIVILEGE),
        "expected insufficient_privilege, got: {denied}"
    );

    sqlx::query(&create)
        .execute(&migrator)
        .await
        .expect("attome_migrator must be able to CREATE TABLE in the schema");
    sqlx::query(&format!(r#"DROP TABLE "{table}""#))
        .execute(&migrator)
        .await
        .expect("drop the probe table");
}

#[tokio::test]
async fn reconcile_relationship_creates_the_join_table_as_the_migrator_role() {
    let url = skip_if_no_db!(attome_testkit::migrated_db_url());
    let (state, runtime, migrator) = split_role_state(&url).await;

    // Endpoint entity tables are provisioned the way the server does it:
    // through the migrator pool.
    let entity_a = unique_logicalname("rdi_a");
    let entity_b = unique_logicalname("rdi_b");
    for logicalname in [&entity_a, &entity_b] {
        let desc = EntityDesc {
            logicalname: logicalname.clone(),
            display_name: logicalname.clone(),
            primary_name_attribute: None,
            is_append_only: false,
            is_audited: false,
            category: None,
            storage_mode: Default::default(),
        };
        reconcile_entity(&migrator, &desc, ReconcilePolicy::Seed)
            .await
            .unwrap_or_else(|e| panic!("provision endpoint entity {logicalname}: {e}"));
    }

    let simple = Uuid::now_v7().simple().to_string();
    let name = format!("rdi_{}", &simple[simple.len() - 12..]);
    let desc = RelationshipDesc {
        name: name.clone(),
        entity_a: entity_a.clone(),
        entity_b: entity_b.clone(),
        role_a: "a".into(),
        role_b: "b".into(),
        cascade: RelationshipCascade::Orphan,
        is_active: true,
    };

    let (_detail, outcome) = reconcile_relationship(&state, &desc, ReconcilePolicy::Admin, None)
        .await
        .unwrap_or_else(|e| {
            panic!("reconcile_relationship must create the join table through db_migrator: {e}")
        });
    assert_eq!(outcome, ReconcileOutcome::Created);

    let join_table = format!("mm_{name}");
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT tableowner::text FROM pg_tables \
         WHERE schemaname = current_schema() AND tablename = $1",
    )
    .bind(&join_table)
    .fetch_optional(&runtime)
    .await
    .expect("look up the join table owner");
    assert_eq!(
        owner.as_deref(),
        Some("attome_migrator"),
        "the join table must be created by the provisioning identity"
    );

    // 0042's default privileges on migrator-created tables are what let the
    // runtime role read and write join rows afterwards.
    let runtime_can_write: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('attome_runtime', $1::regclass, 'INSERT') \
            AND has_table_privilege('attome_runtime', $1::regclass, 'DELETE')",
    )
    .bind(&join_table)
    .fetch_one(&runtime)
    .await
    .expect("check runtime privileges on the join table");
    assert!(
        runtime_can_write,
        "attome_runtime must be able to write join rows in a migrator-created join table"
    );
}
