//! M27 Phase 1 (KPI & Metrics, D-407) money path: snapshot idempotency and
//! the restatement chain, exercised directly against
//! `metric.rs::compute_and_record` — same test shape as
//! `attome-dashboard/tests/dashboard_crud.rs` exercising `lifecycle.rs`'s
//! `do_*` functions directly rather than standing up a full authenticated
//! HTTP request. Moved here (verbatim apart from `seed_once`, which no
//! longer routes through `attome-dashboard`'s bundle-backed fixtures — this
//! crate has no reverse dependency on it) by D-480 (M26 R-14).
//!
//! Requires a live Postgres (`DATABASE_URL`) with migration
//! `0160_metric_snapshot.sql` applied — skips (loudly) when `DATABASE_URL`
//! is unset, except under `CI`, per the P1.8 testing-baseline convention.
//!
//! D-786: query-backed metrics run through `query_exec` under the metric
//! service principal, so the suite builds a real `EngineState` and needs Redis
//! too (`TEST_REDIS_PORT`, the test profile's 6380).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-metric --test metric -- --test-threads=1
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
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_testkit::skip_if_no_db;

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_metric::principal::{METRIC_PRINCIPAL_ID, METRIC_SNAPSHOT_PRIVILEGE};
use attome_server::AppState;
use chrono::NaiveDate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use uuid::Uuid;

/// Same shape as `attome-records/tests/upsert.rs::test_config`: the infra
/// a full `EngineState` needs (Postgres + Redis + storage client).
fn test_config(direct_url: &str) -> AppConfig {
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
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 5, "timeout": 5.0,
                "direct_url": "{direct_url}"
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
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
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
        direct_url = direct_url,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

// SAFETY: `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` from the
// environment before its first `.await`; this lock serializes the `set_var`
// below across this binary's concurrently running tests (same convention as
// `attome-records/tests/upsert.rs`).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A real `EngineState` over the throwaway test database. `readonly` replaces the
/// state's `db_readonly` (the pool `query_exec` runs stored SQL on); `None`
/// reuses the primary pool, which is enough for every test that is not about
/// pool separation.
async fn test_state(readonly: Option<DbPool>) -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url);
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
    let db_readonly = readonly.unwrap_or_else(|| db.clone());
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
    Some(EngineState::new(base))
}

/// R-06: a genuine SELECT-only `attome_readonly` pool against this same
/// throwaway database, for the one test that needs to prove
/// `run_query_metric` actually runs the wrapped user SQL on that role and
/// not on `db`. Migration `0010_readonly_query_role.sql` creates the role
/// structurally (`NOLOGIN`, no password) in every migrated database,
/// including each per-binary throwaway clone `test_db_url` hands back — this
/// mirrors `attome-api/tests/query_exec.rs`'s own `synchronize_readonly_login`
/// (that helper lives in a different crate's test binary, so it can't be
/// imported directly) to grant `LOGIN` and set the password before
/// connecting, and requires the same `READONLY_DB_PASSWORD` env var CI/
/// `scripts/run-integration-tests.ps1` already set for that suite.
async fn readonly_db(db: &DbPool) -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    let password = std::env::var("READONLY_DB_PASSWORD")
        .unwrap_or_else(|_| "test-only-readonly-password".to_owned());

    let mut tx = db
        .begin()
        .await
        .expect("open readonly-role seed transaction");
    sqlx::query("SELECT set_config('attome.readonly_password', $1, true)")
        .bind(&password)
        .execute(&mut *tx)
        .await
        .expect("stage readonly test credential");
    sqlx::query(
        r#"
        DO $$
        BEGIN
            EXECUTE format(
                'ALTER ROLE attome_readonly WITH LOGIN PASSWORD %L',
                current_setting('attome.readonly_password')
            );
        END
        $$;
        "#,
    )
    .execute(&mut *tx)
    .await
    .expect("apply readonly test credential");
    tx.commit()
        .await
        .expect("commit readonly-role seed transaction");

    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL must be a valid postgres:// URL")
        .username("attome_readonly")
        .password(&password);
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .expect("connect attome_readonly role"),
    )
}

/// D-480 (M26 R-14): this crate has no reverse dependency on `attome-dashboard`
/// (the dependency edge runs the other way), so this fixture seeds only what
/// `platform-bundles/attome-metric.json` needs — `user_account` (the
/// `owner_ref` lookup target), via `attome_security::seed::seed_for_tests` —
/// rather than going through `attome_dashboard::seed::seed_for_tests`'s
/// platform-bundle walk the way the pre-split version of this file did
/// (that bundle provisions dashboard-family entities this suite never
/// touches).
async fn seed_once(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    // `SecurityTx` (the principal's one-time provisioning event) writes an
    // audit header, which resolves its entity metadata.
    attome_audit::seed(db)
        .await
        .expect("seed audit entity metadata");
    attome_metric::metric::seed_for_tests(db)
        .await
        .expect("attome_metric::metric::seed_for_tests");
}

/// A stored query plus one published version, inserted bare (this suite tests
/// metric compute, not query publishing). `relations` stays `{}`, the shape a
/// platform-bundle query has, so record scope adds nothing and only
/// `required_privilege` decides whether the principal may run it.
async fn insert_query(db: &DbPool, sql: &str, required_privilege: Option<&str>) -> (Uuid, Uuid) {
    let query_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, required_privilege, is_active, is_report, owner_layer) \
         VALUES ($1, $2, $3, true, true, 'project')",
    )
    .bind(query_id)
    .bind(sql)
    .bind(required_privilege)
    .execute(db)
    .await
    .expect("insert sql_query row");
    let version_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query_version (id, query_id, sql_query, cost_estimate) \
         VALUES ($1, $2, $3, 0)",
    )
    .bind(version_id)
    .bind(query_id)
    .bind(sql)
    .execute(db)
    .await
    .expect("insert sql_query_version row");
    (query_id, version_id)
}

async fn insert_query_metric(db: &DbPool, query_id: Uuid) -> Uuid {
    let metric_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
         (id, name, key, source_kind, query_ref, direction, period) \
         VALUES ($1, $2, $3, 'query', $4, 'higher_is_better', 'month')",
    )
    .bind(metric_id)
    .bind(format!("Query Metric {metric_id}"))
    .bind(format!("query_metric_{metric_id}"))
    .bind(query_id.to_string())
    .execute(db)
    .await
    .expect("insert query metric definition");
    metric_id
}

/// Bypasses the generic entity engine and `metric.rs`'s own seed-time choice
/// validation (same reason `attome-dashboard/tests/dashboard_crud.rs::insert_dashboard`
/// inserts a bare row) — this suite tests `metric.rs`'s compute/snapshot
/// logic directly, not entity CRUD.
async fn insert_manual_metric(db: &DbPool, direction: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition (id, name, key, source_kind, direction, period) \
         VALUES ($1, $2, $3, 'manual', $4, 'month')",
    )
    .bind(id)
    .bind(format!("Test Metric {id}"))
    .bind(format!("test_metric_{id}"))
    .bind(direction)
    .execute(db)
    .await
    .expect("insert test dashboard_metric_definition row");
    id
}

async fn snapshot_rows_for(
    db: &DbPool,
    metric_id: Uuid,
    period_start: NaiveDate,
) -> Vec<(Uuid, f64, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT id, actual, superseded_ref FROM metric_snapshot \
         WHERE metric_ref = $1 AND period_start = $2 ORDER BY computed_at",
    )
    .bind(metric_id)
    .bind(period_start)
    .fetch_all(db)
    .await
    .expect("read metric_snapshot rows")
}

#[tokio::test]
async fn running_the_snapshot_twice_for_the_same_period_produces_one_row_not_two() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let metric_id = insert_manual_metric(&db, "higher_is_better").await;
    let period_start = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
    let evaluator = Some(Uuid::now_v7());

    let first = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        Some(42.0),
        false,
        evaluator,
    )
    .await
    .expect("first compute");
    assert!(
        !first.skipped,
        "the first compute must actually write a row"
    );
    assert_eq!(first.snapshot.actual, Some(42.0));
    assert_eq!(first.snapshot.superseded_ref, None);

    // Idempotent re-run: same metric, same period, force=false. This is
    // exactly what the scheduled sweep does on its next tick before the
    // period rolls over — it must not write a second row.
    let second = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        Some(999.0), // even with a different candidate actual, the skip wins
        false,
        evaluator,
    )
    .await
    .expect("second compute");
    assert!(
        second.skipped,
        "a non-forced recompute for an already-computed period must be a no-op"
    );
    assert_eq!(
        second.snapshot.id, first.snapshot.id,
        "the skip must return the existing row, not a new one"
    );
    assert_eq!(
        second.snapshot.actual,
        Some(42.0),
        "the original value must survive an idempotent re-run untouched"
    );

    let rows = snapshot_rows_for(&db, metric_id, period_start).await;
    assert_eq!(
        rows.len(),
        1,
        "running the job twice for the same period must produce exactly one snapshot row"
    );
}

#[tokio::test]
async fn a_forced_recompute_writes_a_new_row_chained_by_superseded_ref_and_leaves_the_old_row_untouched()
 {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let metric_id = insert_manual_metric(&db, "higher_is_better").await;
    let period_start = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let evaluator = Some(Uuid::now_v7());

    let original = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        Some(10.0),
        false,
        evaluator,
    )
    .await
    .expect("original compute");
    assert!(!original.skipped);

    // A data correction is discovered later — an admin restates the period.
    let restated = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        Some(15.0),
        true, // force — D-407's restatement path
        evaluator,
    )
    .await
    .expect("restated compute");
    assert!(
        !restated.skipped,
        "force=true must always write, even though a snapshot already exists"
    );
    assert_ne!(restated.snapshot.id, original.snapshot.id);
    assert_eq!(restated.snapshot.actual, Some(15.0));
    assert_eq!(
        restated.snapshot.superseded_ref,
        Some(original.snapshot.id),
        "the new row must chain to the row it replaces"
    );

    // D-407's core guarantee: the original row is never rewritten.
    let rows = snapshot_rows_for(&db, metric_id, period_start).await;
    assert_eq!(
        rows.len(),
        2,
        "a restatement adds a row, it never replaces one"
    );
    let original_row = rows
        .iter()
        .find(|(id, _, _)| *id == original.snapshot.id)
        .expect("original row must still exist");
    assert_eq!(
        original_row.1, 10.0,
        "the superseded row's own actual value must be untouched — it is history, not a working copy"
    );
    assert_eq!(
        original_row.2, None,
        "the superseded row's own superseded_ref must remain NULL — only the new row points backward"
    );

    // The trend endpoint's own query (list_snapshots) must surface both rows,
    // not just the current one — a restatement's full history stays visible.
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metric_snapshot WHERE metric_ref = $1")
            .bind(metric_id)
            .fetch_one(&db)
            .await
            .expect("count snapshots");
    assert_eq!(total, 2);
}

#[tokio::test]
async fn a_failed_query_metric_is_recorded_as_failed_and_is_not_treated_as_current() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    // source_kind=query with a query_ref that resolves to nothing published
    // — run_query_metric must fail cleanly, and compute_and_record must
    // record that as a real, visible `failed` snapshot rather than
    // propagating an error that would silently drop the attempt.
    let metric_id = Uuid::now_v7();
    let bogus_query_ref = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
         (id, name, key, source_kind, query_ref, direction, period) \
         VALUES ($1, $2, $3, 'query', $4, 'higher_is_better', 'month')",
    )
    .bind(metric_id)
    .bind(format!("Broken Metric {metric_id}"))
    .bind(format!("broken_metric_{metric_id}"))
    .bind(bogus_query_ref.to_string())
    .execute(&db)
    .await
    .expect("insert test broken metric");

    let period_start = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
    let outcome = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        None,
        false,
        None,
    )
    .await
    .expect("compute_and_record itself must not error for a broken query");
    assert!(!outcome.skipped);
    assert_eq!(outcome.snapshot.status, "failed");
    assert_eq!(outcome.snapshot.actual, None);
    // R-06: the raw driver/validation detail never lands in a persisted
    // snapshot row (guidelines §6 — never expose raw DB errors) — only a
    // masked, operator-actionable message pointing at the server log.
    let msg = outcome
        .snapshot
        .error_message
        .as_deref()
        .expect("a failed query-backed compute must still record a message");
    assert!(
        !msg.contains("relation") && !msg.contains("syntax") && !msg.contains("42"),
        "error_message must not leak raw SQL/driver detail: {msg:?}"
    );

    // A subsequent sweep tick must retry a failed period rather than
    // treating it as already-computed.
    let retried = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        None,
        false,
        None,
    )
    .await
    .expect("retry compute");
    assert!(
        !retried.skipped,
        "a failed snapshot must not be treated as a completed computation for this period"
    );
}

#[tokio::test]
async fn scheduled_sweep_processes_query_metrics_without_error() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    // source_kind='query' is the shape `run_scheduled_snapshot_sweep`
    // selects — before R-01's fix, `MetricDefinitionRow`'s SELECT in the
    // sweep omitted the `formula` column, and sqlx's `FromRow` derive (no
    // `#[sqlx(default)]` on that field) turned the very first such row into
    // a `ColumnNotFound` error for the whole sweep tick, not just this one
    // metric. A bogus `query_ref` (same shape as the "failed query is
    // recorded as failed" test above) is enough to exercise the row hydration
    // — the sweep must still record it as a `failed` snapshot, per its
    // documented failure-isolation contract, not propagate the error.
    let metric_id = Uuid::now_v7();
    let bogus_query_ref = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
         (id, name, key, source_kind, query_ref, direction, period) \
         VALUES ($1, $2, $3, 'query', $4, 'higher_is_better', 'month')",
    )
    .bind(metric_id)
    .bind(format!("Sweep Metric {metric_id}"))
    .bind(format!("sweep_metric_{metric_id}"))
    .bind(bogus_query_ref.to_string())
    .execute(&db)
    .await
    .expect("insert test query metric");

    let result = attome_metric::metric::run_scheduled_snapshot_sweep(&state).await;
    assert!(
        result.is_ok(),
        "the sweep must not error on a ColumnNotFound for `formula`: {result:?}"
    );

    let snapshot: (String,) = sqlx::query_as(
        "SELECT status FROM metric_snapshot WHERE metric_ref = $1 \
         ORDER BY computed_at DESC LIMIT 1",
    )
    .bind(metric_id)
    .fetch_one(&db)
    .await
    .expect("sweep must have written a snapshot row for this metric");
    assert_eq!(
        snapshot.0, "failed",
        "a bogus query_ref is recorded as a failed snapshot, not raised as an error"
    );
}

// ── R-06: query-backed metrics must run on the readonly pool ──────────────

#[tokio::test]
async fn a_query_backed_metric_that_tries_to_write_fails_under_the_readonly_pool_and_is_masked() {
    let primary = skip_if_no_db!(test_state(None).await);
    let db = primary.base.db.clone();
    let Some(readonly) = readonly_db(&db).await else {
        // `test_db()` above already handled "no test database configured" —
        // reaching `None` here means `test_db_url()` returned `Some` for
        // `db` but `None` for this second call, which cannot happen (both
        // read the same cached value). Kept only so a future refactor that
        // makes them diverge fails loudly instead of silently skipping.
        panic!("readonly_db returned None after test_db() already found a database");
    };
    seed_once(&db).await;

    // A SELECT that *indirectly* performs a write via a SECURITY INVOKER
    // (the plpgsql default) function. A bare top-level `INSERT ...` — or a
    // data-modifying `WITH` — can't even be wrapped as
    // `run_query_metric`'s `(<sql>) AS t` subquery: Postgres rejects a
    // data-modifying WITH that isn't at the query's top level as a syntax
    // error (verified against this same image, PostgreSQL 18), regardless
    // of role. Calling a function is the shape that actually exercises the
    // `attome_readonly` role's own privilege check rather than just the
    // parser — proving the pool, not just the wrapping, is what stops this.
    let marker = format!("readonly_probe_{}", Uuid::now_v7().simple());
    let func_name = format!("dashboard_test_readonly_probe_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE FUNCTION {func_name}() RETURNS uuid LANGUAGE plpgsql AS $BODY$ \
         DECLARE new_id uuid; \
         BEGIN \
             INSERT INTO dashboard_metric_definition (id, name, key, source_kind, direction, period) \
             VALUES (gen_random_uuid(), 'Injected', '{marker}', 'manual', 'higher_is_better', 'month') \
             RETURNING id INTO new_id; \
             RETURN new_id; \
         END; \
         $BODY$"
    ))
    .execute(&db)
    .await
    .expect("create throwaway probe function");

    // `attome_metric.snapshot` so the principal clears query_exec's privilege
    // gate and the SQL actually reaches the readonly pool (D-786).
    let (query_id, _) = insert_query(
        &db,
        &format!("SELECT {func_name}() AS value"),
        Some(METRIC_SNAPSHOT_PRIVILEGE),
    )
    .await;
    let metric_id = insert_query_metric(&db, query_id).await;

    let state = test_state(Some(readonly))
        .await
        .expect("test database already found above");
    let period_start = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
    let outcome = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        None,
        false,
        None,
    )
    .await
    .expect("compute_and_record itself must not error for a rejected write");

    assert_eq!(outcome.snapshot.status, "failed");
    assert_eq!(outcome.snapshot.actual, None);
    let msg = outcome
        .snapshot
        .error_message
        .as_deref()
        .expect("a failed query-backed compute must still record a message");
    assert!(
        msg.contains("see server logs"),
        "the readonly-role permission failure must be masked, not passed through: {msg:?}"
    );
    for leak in [
        "relation",
        "syntax",
        "permission",
        "denied",
        "INSERT",
        "42501",
    ] {
        assert!(
            !msg.contains(leak),
            "error_message leaked raw DB detail {leak:?}: {msg:?}"
        );
    }

    // The real proof: the function's INSERT must never have landed. If
    // `run_query_metric` ever regresses to running this SQL on `db` instead
    // of `readonly`, this row would exist.
    let inserted: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM dashboard_metric_definition WHERE key = $1")
            .bind(&marker)
            .fetch_optional(&db)
            .await
            .expect("check whether the probe function's insert went through");
    assert!(
        inserted.is_none(),
        "a query-backed metric's stored SQL must never be able to write data \
         (readonly pool + wrapped-subquery, D-407/P1.1e)"
    );
}

// ── formula source (REVIEW-2026-09-02's M27 formula fix) ──────────────────

/// A metric with an explicit `key` (unlike `insert_manual_metric`, which
/// only needs a caller-opaque id) — a formula references another metric by
/// this exact string.
async fn insert_metric(db: &DbPool, key: &str, source_kind: &str, formula: Option<&str>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
            (id, name, key, source_kind, formula, direction, period) \
         VALUES ($1, $2, $3, $4, $5, 'higher_is_better', 'month')",
    )
    .bind(id)
    .bind(format!("Test Metric {key}"))
    .bind(key)
    .bind(source_kind)
    .bind(formula)
    .execute(db)
    .await
    .expect("insert test dashboard_metric_definition row");
    id
}

#[tokio::test]
async fn a_formula_referencing_two_metrics_computes_correctly() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;
    let period_start = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();

    let revenue_key = format!("revenue_{}", Uuid::now_v7().simple());
    let cost_key = format!("cost_{}", Uuid::now_v7().simple());
    let revenue = insert_metric(&db, &revenue_key, "manual", None).await;
    let cost = insert_metric(&db, &cost_key, "manual", None).await;

    attome_metric::metric::compute_and_record(
        &state,
        revenue,
        Some(period_start),
        Some(1000.0),
        false,
        None,
    )
    .await
    .expect("seed revenue snapshot");
    attome_metric::metric::compute_and_record(
        &state,
        cost,
        Some(period_start),
        Some(400.0),
        false,
        None,
    )
    .await
    .expect("seed cost snapshot");

    let formula_id = insert_metric(
        &db,
        &format!("margin_{m}", m = Uuid::now_v7().simple()),
        "formula",
        Some(&format!("{revenue_key} - {cost_key}")),
    )
    .await;

    let outcome = attome_metric::metric::compute_and_record(
        &state,
        formula_id,
        Some(period_start),
        None,
        false,
        None,
    )
    .await
    .expect("compute_and_record itself must not error");
    assert_eq!(outcome.snapshot.status, "ok");
    assert_eq!(outcome.snapshot.actual, Some(600.0));
    assert_eq!(outcome.snapshot.source_version.as_deref(), Some("formula"));
}

#[tokio::test]
async fn a_formula_referencing_a_metric_with_no_snapshot_fails_cleanly_not_a_panic() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;
    let period_start = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();

    let formula_id = insert_metric(
        &db,
        &format!("broken_{m}", m = Uuid::now_v7().simple()),
        "formula",
        Some("no_such_metric_key * 2"),
    )
    .await;

    let outcome = attome_metric::metric::compute_and_record(
        &state,
        formula_id,
        Some(period_start),
        None,
        false,
        None,
    )
    .await
    .expect("compute_and_record itself must not error for an unresolvable reference");
    assert_eq!(outcome.snapshot.status, "failed");
    assert_eq!(outcome.snapshot.actual, None);
    assert!(
        outcome
            .snapshot
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("no_such_metric_key"),
        "error_message must name the unresolved key: {:?}",
        outcome.snapshot.error_message
    );
}

#[tokio::test]
async fn an_override_map_changes_the_result_without_mutating_the_underlying_snapshot() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;
    let period_start = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();

    let revenue_key = format!("rev_{}", Uuid::now_v7().simple());
    let revenue = insert_metric(&db, &revenue_key, "manual", None).await;
    attome_metric::metric::compute_and_record(
        &state,
        revenue,
        Some(period_start),
        Some(1000.0),
        false,
        None,
    )
    .await
    .expect("seed revenue snapshot");

    let baseline = attome_metric::metric::evaluate_formula_metric(
        &db,
        &format!("{revenue_key} * 2"),
        period_start,
        None,
    )
    .await
    .expect("baseline eval");
    assert_eq!(baseline, 2000.0);

    let mut overrides = std::collections::HashMap::new();
    overrides.insert(revenue_key.clone(), 5000.0);
    let scenario_value = attome_metric::metric::evaluate_formula_metric(
        &db,
        &format!("{revenue_key} * 2"),
        period_start,
        Some(&overrides),
    )
    .await
    .expect("override eval");
    assert_eq!(scenario_value, 10000.0);

    // The override must not have written back to the underlying metric.
    let still_original: (Option<f64>,) = sqlx::query_as(
        "SELECT actual FROM metric_snapshot WHERE metric_ref = $1 AND period_start = $2 \
         ORDER BY computed_at DESC LIMIT 1",
    )
    .bind(revenue)
    .bind(period_start)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(still_original.0, Some(1000.0));
}

/// R-13 item 4: `compute_and_record`'s bad-`source_kind` arm is client data
/// (the metric definition's own `source_kind` column), not an internal
/// invariant — must surface as `Validation` (422), not `Internal` (500).
/// Inserts a bare row with a `source_kind` no seeded choice list allows
/// (bypassing the entity engine, same reason `insert_manual_metric` does)
/// so `compute_and_record`'s match falls through to its `other` arm.
#[tokio::test]
async fn compute_and_record_rejects_an_unknown_source_kind_as_validation() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let metric_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition (id, name, key, source_kind, direction, period) \
         VALUES ($1, $2, $3, 'bogus_kind', 'higher_is_better', 'month')",
    )
    .bind(metric_id)
    .bind(format!("Test Metric {metric_id}"))
    .bind(format!("test_metric_{metric_id}"))
    .execute(&db)
    .await
    .expect("insert test dashboard_metric_definition row with an unknown source_kind");

    let period_start = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
    let result = attome_metric::metric::compute_and_record(
        &state,
        metric_id,
        Some(period_start),
        None,
        false,
        None,
    )
    .await;
    // `ComputeOutcome` (the `Ok` type) isn't `Debug`, so `expect_err`/
    // `unwrap_err` don't compile here — match by hand instead.
    match result {
        Ok(_) => panic!("an unknown source_kind must be rejected"),
        Err(err) => assert!(
            matches!(err, attome_types::AppError::Validation(_)),
            "expected Validation, got {err:?}"
        ),
    }
}

// ── D-786: the metric service principal ─────────────────────────────────────

async fn compute_query_metric(
    state: &EngineState,
    metric_id: Uuid,
) -> attome_metric::metric::SnapshotRow {
    attome_metric::metric::compute_and_record(
        state,
        metric_id,
        Some(NaiveDate::from_ymd_opt(2026, 8, 1).unwrap()),
        None,
        true,
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("compute_and_record itself must not error: {e:?}"))
    .snapshot
}

/// The money path: an opted-in query runs under the principal and records its
/// value, pinned to the version that produced it.
#[tokio::test]
async fn the_principal_runs_an_opted_in_query_and_records_the_pinned_version() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let (query_id, version_id) = insert_query(
        &db,
        "SELECT 42::float8 AS value",
        Some(METRIC_SNAPSHOT_PRIVILEGE),
    )
    .await;
    let metric_id = insert_query_metric(&db, query_id).await;

    let snapshot = compute_query_metric(&state, metric_id).await;
    assert_eq!(snapshot.status, "ok", "{:?}", snapshot.error_message);
    assert_eq!(snapshot.actual, Some(42.0));
    assert_eq!(
        snapshot.source_version.as_deref(),
        Some(version_id.to_string().as_str())
    );

    let (active, holds_role): (Option<bool>, bool) = sqlx::query_as(
        "SELECT u.is_active, EXISTS (SELECT 1 FROM user_account_mm_role ur \
                JOIN role r ON r.id = ur.role_ref \
                WHERE ur.user_ref = u.id AND ur.is_deleted = false AND r.name = 'Metric Service') \
         FROM user_account u WHERE u.id = $1",
    )
    .bind(METRIC_PRINCIPAL_ID)
    .fetch_one(&db)
    .await
    .expect("the principal was provisioned on first use");
    assert_eq!(active, Some(true));
    assert!(holds_role, "the principal holds the Metric Service role");
}

/// Narrow role: a stored query that has not opted in (no required_privilege,
/// so admin-only) is refused, and the snapshot fails closed with an
/// actionable, masked message.
#[tokio::test]
async fn a_query_the_principal_may_not_run_fails_closed() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let (query_id, _) = insert_query(&db, "SELECT 7::float8 AS value", None).await;
    let metric_id = insert_query_metric(&db, query_id).await;

    let snapshot = compute_query_metric(&state, metric_id).await;
    assert_eq!(snapshot.status, "failed");
    assert_eq!(snapshot.actual, None);
    let msg = snapshot.error_message.unwrap_or_default();
    assert!(msg.contains("Metric Service"), "{msg:?}");
}

/// Kill switch: an inactive principal computes nothing.
#[tokio::test]
async fn a_disabled_principal_fails_closed() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let (query_id, _) = insert_query(
        &db,
        "SELECT 1::float8 AS value",
        Some(METRIC_SNAPSHOT_PRIVILEGE),
    )
    .await;
    let metric_id = insert_query_metric(&db, query_id).await;
    // First use provisions the principal.
    assert_eq!(compute_query_metric(&state, metric_id).await.status, "ok");

    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(METRIC_PRINCIPAL_ID)
        .execute(&db)
        .await
        .expect("disable the principal");
    let snapshot = compute_query_metric(&state, metric_id).await;
    let still_inactive: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(METRIC_PRINCIPAL_ID)
            .fetch_one(&db)
            .await
            .expect("read principal");
    sqlx::query("UPDATE user_account SET is_active = true WHERE id = $1")
        .bind(METRIC_PRINCIPAL_ID)
        .execute(&db)
        .await
        .expect("re-enable the principal");

    assert_eq!(snapshot.status, "failed");
    assert!(
        snapshot
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("disabled"),
        "{:?}",
        snapshot.error_message
    );
    assert_eq!(
        still_inactive,
        Some(false),
        "provisioning must never re-activate a principal an admin disabled"
    );
}

/// D-440's "never a superuser", applied to the unattended principal.
#[tokio::test]
async fn a_principal_holding_admin_rights_is_refused() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let (query_id, _) = insert_query(
        &db,
        "SELECT 1::float8 AS value",
        Some(METRIC_SNAPSHOT_PRIVILEGE),
    )
    .await;
    let metric_id = insert_query_metric(&db, query_id).await;
    assert_eq!(compute_query_metric(&state, metric_id).await.status, "ok");

    let admin_privilege: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(attome_security::context::ADMIN_PRIVILEGE_KEY)
        .fetch_one(&db)
        .await
        .expect("the admin privilege is seeded");
    let grant_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(grant_id)
    .bind(METRIC_PRINCIPAL_ID)
    .bind(admin_privilege)
    .execute(&db)
    .await
    .expect("grant admin to the principal");
    let snapshot = compute_query_metric(&state, metric_id).await;
    sqlx::query("DELETE FROM user_account_mm_privilege WHERE id = $1")
        .bind(grant_id)
        .execute(&db)
        .await
        .expect("revoke the admin grant");

    assert_eq!(snapshot.status, "failed");
    assert!(
        snapshot
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("administrator"),
        "{:?}",
        snapshot.error_message
    );
}

/// The sweep records the principal — a real system user, no longer the nil
/// UUID — as the evaluator.
#[tokio::test]
async fn the_scheduled_sweep_records_the_principal_as_evaluator() {
    let state = skip_if_no_db!(test_state(None).await);
    let db = state.base.db.clone();
    seed_once(&db).await;

    let (query_id, _) = insert_query(
        &db,
        "SELECT 3::float8 AS value",
        Some(METRIC_SNAPSHOT_PRIVILEGE),
    )
    .await;
    let metric_id = insert_query_metric(&db, query_id).await;
    attome_metric::metric::run_scheduled_snapshot_sweep(&state)
        .await
        .expect("sweep");

    let (status, actual, evaluated_by): (String, Option<f64>, Option<Uuid>) = sqlx::query_as(
        "SELECT status, actual, evaluated_by FROM metric_snapshot WHERE metric_ref = $1 \
         ORDER BY computed_at DESC LIMIT 1",
    )
    .bind(metric_id)
    .fetch_one(&db)
    .await
    .expect("the sweep wrote a snapshot");
    assert_eq!(status, "ok");
    assert_eq!(actual, Some(3.0));
    assert_eq!(evaluated_by, Some(METRIC_PRINCIPAL_ID));
}
