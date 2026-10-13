//! Solution 7 Phase 1.5 (D-785, design §5.7, plan 1.5) — the platform's
//! own definitions apply at boot from the compiled `changesets/platform/*.json`
//! through the applied-changeset ledger (the only path since 2026-10-02, when
//! the bundles-vs-changesets equivalence run passed and the watermark-gated
//! bundle path was removed).
//!
//! Boots one **empty** database through the real `attome::boot::init`, checks
//! every compiled platform changeset is in the ledger exactly once (applied by
//! boot), then boots it a second time and checks nothing moves: the ledger,
//! the canonical metadata export, the owner-layer map and the seeded
//! reference rows are identical (a first boot that left something for a later
//! boot to finish is a defect — e.g. the post-`.build()` backfills).
//!
//! **HEAVY**: one fresh-database boot plus a second. Needs Postgres
//! (`DATABASE_URL`, a role with `CREATEDB`), Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) and `APP_ENV=debug`, exactly like `fresh_bootstrap.rs`
//! (same isolation: a whole throwaway database per boot, never the shared
//! template). Skips loudly without `DATABASE_URL`, except under `CI`.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p server --test changeset_platform_boot -- --test-threads=1
//! ```

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeMap;

use attome_config::AppConfig;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Restores `DATABASE_URL` on drop (see `fresh_bootstrap.rs`: `create_pool`
/// must fall back to the config pointing at the throwaway database).
struct DatabaseUrlGuard {
    original: Option<String>,
}

impl DatabaseUrlGuard {
    /// SAFETY: this file has exactly one test, so nothing else in this
    /// process mutates `DATABASE_URL` concurrently.
    fn unset() -> Self {
        let original = std::env::var("DATABASE_URL").ok();
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }
        Self { original }
    }
}

impl Drop for DatabaseUrlGuard {
    fn drop(&mut self) {
        // SAFETY: see `unset`.
        unsafe {
            match &self.original {
                Some(v) => std::env::set_var("DATABASE_URL", v),
                None => std::env::remove_var("DATABASE_URL"),
            }
        }
    }
}

const DEPLOYMENT_SCHEMA: &str = "attome_dev";

fn test_config(db: &DbUrlParts) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{host}", "port": {port}, "dbname": "{dbname}",
                "user": "{user}", "password": "{password}", "schema": "{schema}",
                "connection_number": 5, "timeout": 5.0, "migrate_on_boot": true
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": true
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
        host = db.host,
        port = db.port,
        dbname = db.dbname,
        user = db.user,
        password = db.password,
        schema = DEPLOYMENT_SCHEMA,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    serde_json::from_str(&json).expect("test config JSON must deserialize into AppConfig")
}

async fn assert_connected_to(pool: &PgPool, expected: &str) {
    let (current,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("SELECT current_database()");
    assert_eq!(
        current, expected,
        "this test only ever writes to its own throwaway database"
    );
}

/// What one boot produced.
struct Snapshot {
    export: String,
    owner_layers: Vec<(String, String, String)>,
    records: BTreeMap<String, Vec<String>>,
}

/// `(kind, logical key, owner_layer)` of every stamped metadata row.
const OWNER_LAYER_SQL: &str = "\
    SELECT 'entity', logicalname, owner_layer FROM entity_info \
     WHERE COALESCE(is_active, true) AND logicalname IS NOT NULL \
    UNION ALL \
    SELECT 'field', e.logicalname || '.' || a.logicalname, a.owner_layer \
      FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
     WHERE COALESCE(a.is_active, true) \
    UNION ALL \
    SELECT 'relationship', name, owner_layer FROM relationship_info \
     WHERE is_deleted = false \
    UNION ALL \
    SELECT 'view', e.logicalname || '.' || v.name, v.owner_layer \
      FROM view v JOIN entity_info e ON e.id = v.entity_logical_name \
     WHERE v.scope = 'system' AND v.is_active \
    UNION ALL \
    SELECT 'query', COALESCE(e.logicalname, '*') || '.' || q.record_no, q.owner_layer \
      FROM sql_query q LEFT JOIN entity_info e \
        ON e.id = q.entity_logical_name \
     WHERE COALESCE(q.is_active, true) AND q.record_no IS NOT NULL \
    UNION ALL \
    SELECT 'role', name, owner_layer FROM role WHERE is_deleted = false \
    UNION ALL \
    SELECT 'privilege', key, owner_layer FROM privilege \
    UNION ALL \
    SELECT 'state_model', entity_logicalname, owner_layer FROM state_model \
     WHERE is_deleted = false \
    UNION ALL \
    SELECT 'sidebar', name || ':' || COALESCE(route, ''), owner_layer FROM sidebar \
     WHERE is_deleted = false \
    ORDER BY 1, 2, 3";

async fn snapshot(db: &PgPool) -> Snapshot {
    let bundle = attome_api::bundle::export_bundle(db)
        .await
        .expect("export_bundle");
    let export = String::from_utf8(attome_api::bundle::canonical_json(&bundle))
        .expect("canonical JSON is UTF-8");
    let owner_layers: Vec<(String, String, String)> = sqlx::query_as(OWNER_LAYER_SQL)
        .fetch_all(db)
        .await
        .expect("read owner layers");

    // Every platform record set's rows: id (derived from the key) and key.
    let mut records = BTreeMap::new();
    for (name, json) in attome_api::changeset::layers::PLATFORM_BUNDLES {
        let bundle: attome_api::bundle::Bundle =
            serde_json::from_str(json).expect("platform bundle parses");
        for rs in &bundle.record_sets {
            assert!(
                rs.entity
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{name}: record-set entity {:?} is not a plain identifier",
                rs.entity
            );
            let rows: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT id::text FROM \"{}\" ORDER BY id",
                rs.entity
            ))
            .fetch_all(db)
            .await
            .expect("read seeded records");
            records.insert(rs.entity.clone(), rows);
        }
    }
    Snapshot {
        export,
        owner_layers,
        records,
    }
}

async fn boot_fresh(db: &attome_testkit::EmptyDatabase) -> (attome::boot::Boot, AppConfig) {
    let parts = DbUrlParts::parse(db.url()).expect("DATABASE_URL must parse");
    let config = test_config(&parts);
    let migration_db = attome_db::create_direct_pool(&config)
        .await
        .expect("connect to the fresh database");
    assert_connected_to(&migration_db, db.name()).await;
    attome_db::ensure_schema(&migration_db, &config)
        .await
        .expect("ensure_schema");
    attome_db::run_migrations(&migration_db, &MIGRATOR)
        .await
        .expect("run_migrations");
    migration_db.close().await;
    let boot = attome::boot::init(&config)
        .await
        .unwrap_or_else(|e| panic!("a fresh boot failed: {e}"));
    assert_connected_to(&boot.system.state().base.db, db.name()).await;
    (boot, config)
}

fn first_difference(a: &str, b: &str) -> String {
    let at = a
        .bytes()
        .zip(b.bytes())
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    let from = at.saturating_sub(300);
    format!(
        "first difference at byte {at}:\n  first boot:  …{}…\n  second boot: …{}…",
        a.get(from..(at + 300).min(a.len())).unwrap_or(""),
        b.get(from..(at + 300).min(b.len())).unwrap_or("")
    )
}

#[tokio::test]
async fn a_fresh_boot_applies_every_platform_changeset_once_and_a_second_boot_moves_nothing() {
    let fresh = skip_if_no_db!(attome_testkit::empty_database("cs_platform_boot").await);
    let _database_url_guard = DatabaseUrlGuard::unset();

    let (first_boot, config) = boot_fresh(&fresh).await;
    let db = &first_boot.system.state().base.db;
    let first = snapshot(db).await;

    // Every compiled platform changeset is in the ledger, applied by boot, once.
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT ref, status, source FROM changeset_apply \
          WHERE layer = 'platform' ORDER BY ref",
    )
    .fetch_all(db)
    .await
    .expect("read the ledger");
    assert_eq!(
        rows.len(),
        attome_api::changeset::platform_index::PLATFORM_CHANGESETS.len(),
        "{rows:?}"
    );
    assert!(
        rows.iter()
            .all(|(_, status, source)| status == "succeeded" && source == "boot"),
        "{rows:?}"
    );

    // A second boot is a no-op: the ledger is unchanged and so is everything else.
    drop(first_boot);
    let again = attome::boot::init(&config).await.expect("a second boot");
    let db = &again.system.state().base.db;
    let after: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT ref, status, source FROM changeset_apply \
          WHERE layer = 'platform' ORDER BY ref",
    )
    .fetch_all(db)
    .await
    .expect("read the ledger again");
    assert_eq!(after, rows);
    let second = snapshot(db).await;
    assert!(
        second.export == first.export,
        "a second boot moved the metadata — {}",
        first_difference(&first.export, &second.export)
    );
    assert!(
        second.owner_layers == first.owner_layers,
        "a second boot moved the owner-layer map"
    );
    assert_eq!(
        second.records, first.records,
        "a second boot moved the seeded reference rows"
    );
}
