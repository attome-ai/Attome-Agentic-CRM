//! P-retention-archive-completion — live-verified against a real Postgres,
//! closing the plan's own named gap: "The full propose -> approve ->
//! execute -> verify round trip end to end... this plan's own §6
//! manual-verification step, explicitly still owed."
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), migration 0067 (`audit_retention_action`) applied,
//! and — for the `partition_archive` tests at the bottom of this file only —
//! a reachable object store matching `test_config`'s `storage` block
//! (`http://localhost:9000`, bucket `attome-test`, the same RustFS/MinIO
//! instance `/release-and-deploy`'s local stack already stands up).
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test retention -- --test-threads=1
//! ```
//!
//! **`partition_archive` coverage (added following D-212's own disclosed
//! gap — "no `partition_archive` case, live or otherwise").** Unlike the
//! `entity_purge` tests above, these two cannot go through
//! `propose_retention_actions`'s real age-based cutoff: on any freshly
//! migrated database, `migrations/0026`'s `{table}_pre_partition` bucket
//! already owns every timestamp from `MINVALUE` through its own cutover
//! month, and `ensure_ahead_partitions` claims several months past that — so
//! there is no free "old" date range left to attach a synthetic aged
//! partition into on the real `audit_detail`/`s2s_access_log`
//! tables (the exact collision `attome-core/tests/partition_archive.rs`'s
//! own header documents, which is why that file uses a throwaway table
//! instead — not an option here, since `execute_partition_archive` only ever
//! accepts a partition of one of the four real tables it recognizes
//! (`parent_table_for_partition`)). Both tests below instead attach a real
//! partition far in the *future* (year 2099, free of any collision) and
//! manufacture an already-`approved` `audit_retention_action` row directly
//! — the same "simulate the admin approval step" pattern the `entity_purge`
//! tests above already use — so `execute_action`'s actual mechanics (detach,
//! stream-export to the live store, re-verify, drop) run for real regardless
//! of whether the partition would ever be proposed by age in production.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_compliance::retention::{execute_action, propose_retention_actions};
use attome_config::AppConfig;
use attome_core::{EngineState, build_registry};
use attome_metadata::provision::{ensure_attribute, ensure_entity};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use uuid::Uuid;

fn test_config(entity_purge_grace_days: Option<u32>, dry_run: bool, legal_hold: bool) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
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
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}", "s3_secret_key": "{s3_secret_key}",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "categories": {{}} }},
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
            "s2s": {{ "enabled": false, "key_encryption_key": "test-only-throwaway-s2s-key-32-bytes-min" }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["http://test.local"] }},
            "retention": {{
                "audit_days": null, "s2s_access_log_days": null,
                "entity_purge_grace_days": {entity_purge_grace_days},
                "legal_hold": {legal_hold}, "dry_run": {dry_run}
            }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        // `S3_ACCESS_KEY`/`S3_SECRET_KEY` (not `TEST_S3_*`) are the names
        // `scripts/run-integration-tests.ps1` actually exports, and the same
        // pair `file_upload_pipeline.rs` reads.
        // These were `TEST_S3_ACCESS_KEY`/`TEST_S3_SECRET_KEY` with a
        // `"test"` fallback — names nothing in this repo sets — so every run
        // silently signed with `test`/`test` and RustFS rejected the upload
        // with `403 InvalidAccessKeyId`. Only surfaced on the multipart
        // completion path because that is where these two suites first do a
        // real S3 write; the failure was never multipart-specific (a plain
        // PUT with the same wrong credentials fails identically). `expect`
        // rather than a default: a wrong-but-plausible fallback is exactly
        // what hid this.
        s3_access_key = attome_testkit::s3_env("S3_ACCESS_KEY"),
        s3_secret_key = attome_testkit::s3_env("S3_SECRET_KEY"),
        entity_purge_grace_days = entity_purge_grace_days
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string()),
        dry_run = dry_run,
        legal_hold = legal_hold,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(mut config: AppConfig) -> Option<EngineSystem> {
    let url = attome_testkit::migrated_db_url()?;
    attome_testkit::s3_or_skip()?;
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis");
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

    let db_readonly = db.clone();
    let db_migrator = db.clone();
    let base = AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    Some(
        EngineSystem::builder(state)
            .register(attome_security::model::SecurityModel)
            .build()
            .await
            .expect("build EngineSystem"),
    )
}

async fn provision_test_entity(db: &attome_db::DbPool) -> String {
    let logicalname = format!("test_retention_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(db, &logicalname, "Test Retention Entity", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        db, entity_id, "ssn", "SSN", "text", false, true, false, false, None, None,
    )
    .await
    .expect("ensure_attribute ssn");
    logicalname
}

async fn seed_soft_deleted_record(
    db: &attome_db::DbPool,
    logicalname: &str,
    days_ago: i64,
) -> Uuid {
    let record_id = Uuid::now_v7();
    let backdated = Utc::now() - ChronoDuration::days(days_ago);
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (id, ssn, is_active, created_at, modified_at) \
         VALUES ($1, 'secret-ssn', false, $2, $2)"
    ))
    .bind(record_id)
    .bind(backdated)
    .execute(db)
    .await
    .expect("seed a soft-deleted test record");
    record_id
}

/// The plan's own named gap, closed: propose creates the action row,
/// directly approving it (mirroring what `retention_admin.rs`'s
/// `POST .../approve` does at the SQL layer, without standing up a full
/// HTTP harness for this pass), execute actually scrubs the record, and the
/// action row itself shows `completed` with an `approved_by`-attributed
/// audit trail — the full state machine, not just its two halves in
/// isolation.
#[tokio::test]
async fn propose_approve_execute_purges_a_record_and_marks_the_action_completed() {
    let config = test_config(Some(90), false, false);
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let logicalname = provision_test_entity(db).await;
    let record_id = seed_soft_deleted_record(db, &logicalname, 400).await;
    let approver = Uuid::now_v7();

    // `execute_entity_purge` resolves via `state.entities.load()` (the
    // arc-swap metadata registry) directly, with no direct-Postgres
    // fallback the way `entity_crud.rs` has — unlike that path, this one
    // needs the registry to actually know about an entity provisioned
    // *after* `EngineSystem::build()` already ran. Force a synchronous
    // rebuild rather than sleeping for the pub/sub refresh interval.
    let fresh_registry = build_registry(db).await.expect("build_registry");
    state.entities.swap(fresh_registry);

    let proposed = propose_retention_actions(state)
        .await
        .expect("propose_retention_actions");
    assert!(
        proposed >= 1,
        "expected at least our seeded record to be proposed"
    );

    let target = format!("{logicalname}:{record_id}");
    let action_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_retention_action WHERE action_type = 'entity_purge' AND target = $1",
    )
    .bind(&target)
    .fetch_one(db)
    .await
    .expect("proposed action row must exist");

    // Simulate the admin approval step (`retention_admin.rs`'s
    // `POST .../approve`, not stood up as an HTTP harness in this pass) —
    // `execute_action` itself only cares that the row reached `approved`
    // with an `approved_by`, not how it got there.
    sqlx::query(
        "UPDATE audit_retention_action SET status = 'approved', approved_by = $2, approved_at = NOW() WHERE id = $1",
    )
    .bind(action_id)
    .bind(approver)
    .execute(db)
    .await
    .expect("simulate approval");

    execute_action(state, action_id)
        .await
        .expect("execute_action");

    let (status, evidence_ref): (String, Option<String>) =
        sqlx::query_as("SELECT status, evidence_ref FROM audit_retention_action WHERE id = $1")
            .bind(action_id)
            .fetch_one(db)
            .await
            .expect("action row must still exist");
    assert_eq!(status, "completed");
    assert!(
        evidence_ref.is_some(),
        "a completed purge should record an evidence_ref"
    );

    let (ssn, is_active): (Option<String>, bool) = sqlx::query_as(&format!(
        "SELECT ssn, is_active FROM \"{logicalname}\" WHERE id = $1"
    ))
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("record must still exist (purge scrubs, never hard-deletes)");
    assert_eq!(ssn, None, "the sensitive field must be nulled by the purge");
    assert!(!is_active, "purge must not resurrect a soft-deleted record");
}

/// §3a/§3e's dry-run safety gate: an approved action must be refused at
/// execute time if `retention.dry_run` is still true, even though approval
/// itself already happened — config can change between approve and execute.
#[tokio::test]
async fn execute_refuses_an_approved_action_while_dry_run_is_true() {
    let config = test_config(Some(90), true, false);
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let logicalname = provision_test_entity(db).await;
    let record_id = seed_soft_deleted_record(db, &logicalname, 400).await;
    propose_retention_actions(state)
        .await
        .expect("propose_retention_actions");

    let target = format!("{logicalname}:{record_id}");
    let action_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_retention_action WHERE action_type = 'entity_purge' AND target = $1",
    )
    .bind(&target)
    .fetch_one(db)
    .await
    .expect("proposed action row must exist");
    sqlx::query(
        "UPDATE audit_retention_action SET status = 'approved', approved_by = $2, approved_at = NOW() WHERE id = $1",
    )
    .bind(action_id)
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("simulate approval");

    let result = execute_action(state, action_id).await;
    assert!(
        result.is_err(),
        "execute_action must refuse an approved action while retention.dry_run is true"
    );

    let (ssn, status): (Option<String>, String) = sqlx::query_as(&format!(
        "SELECT ssn, is_active FROM \"{logicalname}\" WHERE id = $1"
    ))
    .bind(record_id)
    .fetch_one(db)
    .await
    .map(|(ssn, is_active): (Option<String>, bool)| (ssn, is_active.to_string()))
    .expect("record must be untouched");
    assert_eq!(
        ssn,
        Some("secret-ssn".to_string()),
        "dry_run must leave the record unscrubbed"
    );
    let _ = status;
}

/// §3a/§3e's legal-hold kill switch: an approved action must be refused at
/// execute time while `retention.legal_hold` is set — the deployment-wide
/// freeze applies even to an already-approved row.
#[tokio::test]
async fn execute_refuses_an_approved_action_under_legal_hold() {
    let config = test_config(Some(90), false, true);
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let logicalname = provision_test_entity(db).await;
    let record_id = seed_soft_deleted_record(db, &logicalname, 400).await;
    propose_retention_actions(state)
        .await
        .expect("propose_retention_actions");

    let target = format!("{logicalname}:{record_id}");
    let action_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_retention_action WHERE action_type = 'entity_purge' AND target = $1",
    )
    .bind(&target)
    .fetch_one(db)
    .await
    .expect("proposed action row must exist");
    sqlx::query(
        "UPDATE audit_retention_action SET status = 'approved', approved_by = $2, approved_at = NOW() WHERE id = $1",
    )
    .bind(action_id)
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("simulate approval");

    let result = execute_action(state, action_id).await;
    assert!(
        result.is_err(),
        "execute_action must refuse an approved action while retention.legal_hold is set"
    );
}

// ── partition_archive: execute_partition_archive against a real partition ──
// See this file's top doc comment for why these two attach a partition dated
// 2099 and manufacture an `approved` action row directly rather than going
// through `propose_retention_actions`.

/// Attaches a real partition of `table` (must be one of the four tables
/// `attome_api::retention`'s internal `parent_table_for_partition` recognizes
/// — `audit_header`/`_detail`/`_snapshot`/`s2s_access_log`;
/// `execute_partition_archive` refuses anything else) covering January 2099,
/// a date range no migration or create-ahead job could plausibly have
/// already claimed.
async fn create_future_partition(db: &attome_db::DbPool, table: &str) -> String {
    let start = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2099, 2, 1, 0, 0, 0).unwrap();
    let partition_name = format!("{table}_p2099_01");
    // Drop first rather than `CREATE TABLE IF NOT EXISTS ... PARTITION OF`
    // alone. `execute_partition_archive`'s documented failure behavior is to
    // leave a partition DETACHED but not dropped, and a detached table of
    // this exact name makes `IF NOT EXISTS` a silent no-op — the fixture then
    // "succeeds" while the parent has no such partition, and the test fails
    // later with the far more confusing `"..." is not a partition of "..."`.
    // These are fixed-name 2099 fixtures owned solely by this file, so
    // dropping unconditionally is safe and makes the fixture idempotent.
    sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{partition_name}""#))
        .execute(db)
        .await
        .unwrap_or_else(|e| panic!("drop any leftover throwaway partition {partition_name}: {e}"));
    sqlx::query(&format!(
        r#"CREATE TABLE IF NOT EXISTS "{partition_name}" PARTITION OF "{table}"
               FOR VALUES FROM ('{}') TO ('{}') WITH (fillfactor = 100)"#,
        start.to_rfc3339(),
        end.to_rfc3339(),
    ))
    .execute(db)
    .await
    .unwrap_or_else(|e| panic!("create a throwaway future partition of {table}: {e}"));
    partition_name
}

/// Simulates `retention_admin.rs`'s `POST .../approve` at the SQL layer
/// (same convention the `entity_purge` tests above already use) — bypassing
/// `propose_retention_actions` entirely, since a 2099-dated partition is not
/// "old" and would never be proposed by real age-based logic. `execute_action`
/// only cares that the row it reads is `approved` with an `approved_by`, not
/// how it got there.
async fn manufacture_approved_partition_archive_action(
    db: &attome_db::DbPool,
    partition_name: &str,
    approver: Uuid,
) -> Uuid {
    // Clear any row this fixture left behind on an earlier run before
    // re-inserting. `idx_core_retention_action_target` is UNIQUE on
    // (action_type, target) and these two tests use FIXED partition names
    // (the 2099-dated `create_future_partition` fixtures), so without this
    // they pass exactly once per database and then fail forever after with
    // `23505 duplicate key` — on success leaving a `completed` row, on
    // failure a `failed` one. That is what made them look like a "real"
    // multipart-upload bug rather than un-idempotent fixtures: once the
    // credential fault that failed the first run was fixed, the residue
    // from that run kept failing every subsequent one for a different
    // reason. Scoped to this fixture's own `partition_archive` rows —
    // nothing else's state is touched.
    sqlx::query("DELETE FROM audit_retention_action WHERE action_type = 'partition_archive' AND target = $1")
        .bind(partition_name)
        .execute(db)
        .await
        .expect("clear any prior partition_archive fixture row for this target");

    sqlx::query_scalar(
        "INSERT INTO audit_retention_action (action_type, target, status, approved_by, approved_at) \
         VALUES ('partition_archive', $1, 'approved', $2, NOW()) RETURNING id",
    )
    .bind(partition_name)
    .bind(approver)
    .fetch_one(db)
    .await
    .expect("manufacture an approved partition_archive action row")
}

/// D-212's own named gap, closed: `execute_partition_archive` — detach ->
/// stream-masked-export -> verify row count + checksum -> drop — run for
/// real against a live Postgres partition and a live object store, not just
/// the `object_store::memory::InMemory` unit tests in `attome_api::retention`
/// itself. `s2s_access_log` has no `is_sensitive` column, so this
/// proves the unmasked path end to end; the sibling test below proves the
/// masked path.
#[tokio::test]
async fn execute_partition_archive_streams_verifies_and_drops_a_real_partition() {
    let config = test_config(None, false, false);
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let partition_name = create_future_partition(db, "s2s_access_log").await;
    let seeded_ids: Vec<Uuid> = vec![Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
    for id in &seeded_ids {
        sqlx::query(&format!(
            "INSERT INTO \"{partition_name}\" (id, method, path, created_at) \
             VALUES ($1, 'GET', '/test-partition-archive', '2099-01-15T00:00:00Z')"
        ))
        .bind(id)
        .execute(db)
        .await
        .expect("seed a row into the future partition");
    }

    let approver = Uuid::now_v7();
    let action_id =
        manufacture_approved_partition_archive_action(db, &partition_name, approver).await;

    execute_action(state, action_id)
        .await
        .expect("execute_action must archive and drop a real partition end to end");

    let (status, evidence_ref): (String, Option<String>) =
        sqlx::query_as("SELECT status, evidence_ref FROM audit_retention_action WHERE id = $1")
            .bind(action_id)
            .fetch_one(db)
            .await
            .expect("action row must still exist");
    assert_eq!(status, "completed");
    let evidence_ref = evidence_ref.expect("a completed archive should record an evidence_ref");
    assert!(
        evidence_ref.contains(&format!("retention-archives/{partition_name}.ndjson")),
        "evidence_ref should name the archived object's key, got {evidence_ref:?}"
    );
    assert!(
        evidence_ref.contains("rows=3"),
        "evidence_ref should record the exported row count, got {evidence_ref:?}"
    );

    let still_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)")
            .bind(&partition_name)
            .fetch_one(db)
            .await
            .expect("pg_class existence check");
    assert!(
        !still_exists,
        "the partition must be dropped after a successful archive + verify"
    );

    let object_path = ObjectPath::parse(format!("retention-archives/{partition_name}.ndjson"))
        .expect("valid object key");
    let object = state
        .base
        .storage
        .store()
        .get(&object_path)
        .await
        .expect("archived object must exist in the live object store");
    let bytes = object.bytes().await.expect("read archived object bytes");
    let text = std::str::from_utf8(&bytes).expect("archive must be valid UTF-8 NDJSON");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "one NDJSON line per exported row");
    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
        assert_eq!(value["path"].as_str(), Some("/test-partition-archive"));
    }
}

/// Plan §6's masking-parity assertion, run for real: a live `is_sensitive`
/// row's `old_value`/`new_value` must come back `***MASKED***` in the object
/// actually uploaded to a live object store, not just in
/// `masked_select_expr`'s own string-builder unit tests
/// (`attome_api::retention`'s `masking_literal_matches_the_shell_export_scripts_own_masking_sql`
/// and friends).
#[tokio::test]
async fn execute_partition_archive_masks_is_sensitive_columns_in_the_live_archived_object() {
    let config = test_config(None, false, false);
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let partition_name = create_future_partition(db, "audit_detail").await;
    let sensitive_id = Uuid::now_v7();
    let plain_id = Uuid::now_v7();
    sqlx::query(&format!(
        "INSERT INTO \"{partition_name}\" (id, field_name, old_value, new_value, is_sensitive, created_at) \
         VALUES ($1, 'ssn', 'old-secret', 'new-secret', true, '2099-01-15T00:00:00Z')"
    ))
    .bind(sensitive_id)
    .execute(db)
    .await
    .expect("seed a sensitive row");
    sqlx::query(&format!(
        "INSERT INTO \"{partition_name}\" (id, field_name, old_value, new_value, is_sensitive, created_at) \
         VALUES ($1, 'name', 'old-plain', 'new-plain', false, '2099-01-15T00:00:00Z')"
    ))
    .bind(plain_id)
    .execute(db)
    .await
    .expect("seed a non-sensitive row");

    let approver = Uuid::now_v7();
    let action_id =
        manufacture_approved_partition_archive_action(db, &partition_name, approver).await;

    execute_action(state, action_id)
        .await
        .expect("execute_action must archive and drop a real partition end to end");

    let object_path = ObjectPath::parse(format!("retention-archives/{partition_name}.ndjson"))
        .expect("valid object key");
    let object = state
        .base
        .storage
        .store()
        .get(&object_path)
        .await
        .expect("archived object must exist in the live object store");
    let bytes = object.bytes().await.expect("read archived object bytes");
    let text = std::str::from_utf8(&bytes).expect("archive must be valid UTF-8 NDJSON");

    let mut saw_masked = false;
    let mut saw_plain = false;
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
        let row_id = value["id"].as_str().expect("id field must be a string");
        if row_id == sensitive_id.to_string() {
            assert_eq!(value["old_value"].as_str(), Some("***MASKED***"));
            assert_eq!(value["new_value"].as_str(), Some("***MASKED***"));
            saw_masked = true;
        } else if row_id == plain_id.to_string() {
            assert_eq!(value["old_value"].as_str(), Some("old-plain"));
            assert_eq!(value["new_value"].as_str(), Some("new-plain"));
            saw_plain = true;
        }
    }
    assert!(
        saw_masked,
        "expected the is_sensitive row, masked, in the archived object"
    );
    assert!(
        saw_plain,
        "expected the non-sensitive row, unmasked, in the archived object"
    );
}
