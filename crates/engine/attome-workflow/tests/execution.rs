//! Integration tests for the execution engine (P-workflow-engine.md §6).
//! Requires a live, throwaway Postgres (`DATABASE_URL`) — NEVER `attome_dev`.
//! Skips (loudly) when that variable is unset, except under `CI`; see
//! `attome_testkit`.
//!
//! **Hermetic (F-006, TODO-008).** This suite used to score 1 passed / 13
//! failed against a freshly migrated database, every failure reading
//! `execute_instance: Internal("not found")`. The cause was not the workflow
//! engine: `commit_checkpoint` writes an audit event per node run, and
//! `AuditService::write_header` persists it through
//! `attome_metadata::crud::insert("audit_header", …)`, which resolves the
//! entity from `entity_info`. Migrations create that *table* but
//! not its *metadata* — that comes from `attome_audit::seed`, which only ever
//! ran at server boot. So the suite passed only on a database some other
//! suite had already seeded, which is precisely the order-dependence F-006
//! names. `test_state` now calls the seeds it needs itself (see
//! `seed_platform`), so the suite passes standalone on a fresh database.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-workflow --test execution -- --test-threads=1
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

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

/// `direct_url` is the same throwaway database: `scheduler::ExecutionClaim`
/// takes its per-instance lock on `attome_db::create_direct_connection`, which
/// reads `database.direct_url` (falling back to the config's own URL) and —
/// unlike `create_pool` — never the `DATABASE_URL` override. Without it the
/// claim would try to connect to the placeholder dbname below.
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
    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

// SAFETY: `std::env::set_var` is unsafe in edition 2024 — concurrent
// mutation from other threads is a real data race, not just a logical one
// (same hazard `attome_config`'s `PRODUCTION_CONFIG_ENV_LOCK` guards against
// in `attome-config/src/config/tests.rs`). This module's 12 `#[tokio::test]`
// functions all call `test_state()`, which mutates `DATABASE_URL`/
// `APP_ENV`, and `cargo test` runs them concurrently by default. `ENV_LOCK`
// serializes every mutation with the synchronous env reads inside
// `attome_db::create_pool` (env is read before its first `.await`, per its
// own doc comment) that consume them. It's a `tokio::sync::Mutex`, not a
// `std::sync::Mutex`, specifically so the guard can be held across the
// `create_pool().await` below — guidelines §10 forbids holding a blocking
// guard across an `.await`, and this crosses one by construction.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Registers the entity metadata this suite's code paths resolve at
/// runtime. Idempotent (every `ensure_*` is), but guarded by a `OnceCell`
/// anyway so 14 concurrent `test_state()` calls issue one seed pass instead
/// of 14 racing ones.
///
/// Two seeds, for two distinct reasons, both of which used to be supplied
/// only as a side effect of some other suite having run first:
///
/// * `attome_audit::seed` — `scheduler::commit_checkpoint` audits every
///   node-run transition through `attome_metadata::crud::insert`, which resolves
///   `audit_header` from `entity_info`. Without it every test
///   that reaches a checkpoint failed with `Internal("not found")`.
/// * `attome_metadata::autovalue::seed` — the `create_record` node goes through
///   `attome_api::entity_mutation::create_one`, which reads auto-value rules
///   from `autovalue`. That table is itself a metadata-defined
///   entity (see `autovalue.rs`'s header), so migrations do not create it;
///   `attome_api::system`'s boot path does. Without it the create_record
///   test failed with `relation "autovalue" does not exist`.
///
/// The `attome-workflow` platform bundle is deliberately NOT applied: it registers
/// `workflow_definition` for the browsable list/form UI, and nothing
/// here exercises that. The engine's own tables (`workflow_instance`,
/// `…_node_run`, `…_trigger_index`) are written with plain parameterized
/// SQL and need no metadata at all.
///
/// Every `ensure_*` underneath is idempotent, but the `OnceCell` still
/// earns its place: 14 concurrent `test_state()` calls would otherwise
/// issue 14 racing provision passes.
async fn seed_platform(db: &attome_db::DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            attome_audit::seed(db)
                .await
                .expect("seed audit entity metadata");
            attome_metadata::autovalue::seed_for_tests(db)
                .await
                .expect("seed autovalue entity + table");
        })
        .await;
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
    // reads these vars while this guard is held.
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
    seed_platform(&db).await;
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
    Some(EngineState::new(base))
}

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("workflow-exec-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Directly authors + publishes a workflow version, bypassing the HTTP admin
/// layer (already covered by `attome-api`'s `license_gating.rs`) — exercises
/// `graph::validate` + `trigger_index::rebuild_entry_rows` the same way
/// `admin::publish_version` does.
async fn publish_workflow(db: &sqlx::PgPool, logicalname: &str, graph: serde_json::Value) -> Uuid {
    // Unique per call, not just per test — repeated runs against a
    // persistent throwaway database (not torn down between `cargo test`
    // invocations) must never collide on the logicalname unique constraint.
    let logicalname = format!("{logicalname}-{}", Uuid::now_v7());
    let definition_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .fetch_one(db)
    .await
    .expect("insert definition");

    let version_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition_version (definition_id, version_number, graph, status) \
         VALUES ($1, 1, $2, 'draft') RETURNING id",
    )
    .bind(definition_id)
    .bind(&graph)
    .fetch_one(db)
    .await
    .expect("insert draft version");

    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    let schema_hash = attome_workflow::graph::validate(&parsed).expect("graph validates");

    let mut tx = db.begin().await.expect("begin tx");
    sqlx::query(
        "UPDATE workflow_definition_version SET status = 'published', node_schema_hash = $2 WHERE id = $1",
    )
    .bind(version_id)
    .bind(&schema_hash)
    .execute(&mut *tx)
    .await
    .expect("publish version");
    attome_workflow::trigger_index::rebuild_entry_rows(&mut tx, version_id, &parsed)
        .await
        .expect("rebuild entry rows");
    tx.commit().await.expect("commit publish");

    version_id
}

/// Drains the apalis queue for this instance by directly calling
/// `scheduler::execute_instance` in a loop until the instance reaches a
/// terminal or waiting state — equivalent to what the real worker does, but
/// synchronous and deterministic for a test.
async fn run_to_checkpoint(state: &EngineState, instance_id: Uuid) -> String {
    for _ in 0..50 {
        attome_workflow::scheduler::execute_instance(state, instance_id)
            .await
            .expect("execute_instance");
        let status: String =
            sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
                .bind(instance_id)
                .fetch_one(&state.base.db)
                .await
                .expect("read instance status");
        if status != "running" {
            return status;
        }
    }
    panic!("instance {instance_id} did not reach a checkpoint within 50 passes");
}

/// How many live `wait` rows `instance_id` currently owns.
///
/// `resume_node`/`resume_retry` delete a wait row in the same transaction
/// that resumes it (`trigger_index::delete_wait_row`), so "this instance
/// still has a live wait row" and "this instance's wait is unresolved" are
/// the same statement.
async fn wait_row_count(state: &EngineState, instance_id: Uuid) -> u64 {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_trigger_index \
         WHERE role = 'wait' AND instance_id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("count this instance's live wait rows");
    count as u64
}

/// Runs a sweep, then asserts on **`instance_id`'s own** wait rows rather
/// than on `sweep`'s return value.
///
/// `sla_sweep::sweep` scans the whole `workflow_trigger_index` and
/// returns a count across every instance in the database, so asserting on
/// that global number is not hermetic in two distinct ways (F-006,
/// TODO-008):
///
/// * **Within one run.** `cargo test` runs this file's 14 tests
///   concurrently, and each one's `sweep()` resumes the *other* tests' due
///   wait rows too. That is what made this suite score 13/14 on a plain
///   `cargo test -p attome-workflow --test execution` while passing 14/14
///   under `--test-threads=1`: `approval_round_trip_through_base_approval`
///   asserted `resumed == 0` and got `1`, the row belonging to
///   `approval_rejected_decision_takes_the_rejected_port` running alongside
///   it.
/// * **Across runs.** The throwaway Postgres is a persistent container, not
///   a per-run volume. A test that deliberately ends with a still-pending
///   approval leaves its wait row behind; the signal branch of the sweep
///   filters on `kind = 'approval'` with no `resume_at` predicate, so once
///   that request passes its `ttl_hours` and turns `Expired`, every later
///   run's sweep resumes it and inflates the count again.
///
/// Asserting the post-sweep state — not a before/after delta — is what makes
/// this order-independent in *both* directions. A delta would still be racy:
/// a concurrent test's global sweep can resume this instance's row between
/// the decision and the "before" measurement, leaving a delta of 0 for a
/// wait that genuinely did resolve. The resolved/unresolved state is the
/// property each test actually cares about, and it holds no matter which
/// sweep call performed the resume.
async fn sweep_expecting_resolved(state: &EngineState, instance_id: Uuid) {
    attome_workflow::sla_sweep::sweep(state)
        .await
        .expect("sweep");
    assert_eq!(
        wait_row_count(state, instance_id).await,
        0,
        "this instance's wait must be resolved after the sweep"
    );
}

/// The complement of [`sweep_expecting_resolved`]: the sweep must leave this
/// instance's wait row alone. Safe under concurrency in a way the global
/// counter is not — no other test's sweep can resolve *this* instance's wait
/// while its resume condition is still unmet.
async fn sweep_expecting_unresolved(state: &EngineState, instance_id: Uuid, why: &str) {
    let before = wait_row_count(state, instance_id).await;
    assert_eq!(before, 1, "precondition: exactly one live wait row ({why})");
    attome_workflow::sla_sweep::sweep(state)
        .await
        .expect("sweep");
    assert_eq!(wait_row_count(state, instance_id).await, 1, "{why}");
}

/// How many instances this test's own outbox record has started.
async fn instances_for_record(state: &EngineState, record_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM workflow_instance WHERE correlation_entity_id = $1")
        .bind(record_id)
        .fetch_one(&state.base.db)
        .await
        .expect("count instances for this record")
}

/// Bounded poll budget for the entity-dispatch helpers below — 50 passes at
/// 20ms is the same shape as [`run_to_checkpoint`]'s 50-pass loop.
const DISPATCH_POLL_PASSES: usize = 50;

/// Dispatches the entity-change outbox until this test's own record has
/// started its instance.
///
/// `entity_trigger::dispatch_pending` reads the whole feed after one shared
/// cursor (M06 W1) and returns a global count, so under the default parallel
/// runner a sibling test's dispatch can process *this* test's row first — this test's own call then returns 0 even though the row was
/// dispatched, just by somebody else. That makes `started >= 1` exactly as
/// non-hermetic as the `started == 1` it replaced, only rarer, which is why
/// `wait_for_event_resumes_via_entity_trigger_dispatch` still failed the
/// parallel run after the sweep assertions were scoped (F-006, TODO-008).
///
/// Polling the per-record effect is correct whichever dispatcher processed
/// the row, and a start carries the event id under migration 0501's unique
/// index, so a re-read cannot double-start.
async fn dispatch_until_started(state: &EngineState, record_id: Uuid) -> i64 {
    for _ in 0..DISPATCH_POLL_PASSES {
        attome_workflow::entity_trigger::dispatch_pending(state)
            .await
            .expect("dispatch pending events");
        let started = instances_for_record(state, record_id).await;
        if started > 0 {
            return started;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("record {record_id} never started an instance within the poll budget");
}

/// The wait-node analogue of [`dispatch_until_started`]: dispatches until
/// this instance's `entity_event` wait row drains. Same global-claim hazard,
/// same per-instance remedy.
async fn dispatch_until_resumed(state: &EngineState, instance_id: Uuid) {
    for _ in 0..DISPATCH_POLL_PASSES {
        attome_workflow::entity_trigger::dispatch_pending(state)
            .await
            .expect("dispatch matching event");
        if wait_row_count(state, instance_id).await == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("instance {instance_id} was never resumed by a matching entity event");
}

#[tokio::test]
async fn money_path_branch_fan_out_join_completes() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    // trigger -> condition(true branch) -> [a, b] fan-out -> join(update_record on same port) -> (skipped false-branch node)
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "c", "type": "condition", "config": {"op": "truthy"}},
            {"id": "a", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "b", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "dead", "type": "wait", "config": {"delay_seconds": -1}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "c", "to_port": "value"},
            {"from_node": "c", "from_port": "true", "to_node": "a", "to_port": "in"},
            {"from_node": "c", "from_port": "true", "to_node": "b", "to_port": "in"},
            {"from_node": "c", "from_port": "false", "to_node": "dead", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "money-path-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!(true),
    )
    .await
    .expect("start instance");

    // "a"/"b" are Wait nodes with a negative delay (already due) — the SLA
    // sweep resumes them; run passes + sweeps until every node settles.
    let mut status = run_to_checkpoint(&state, instance_id).await;
    for _ in 0..10 {
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep");
        status = run_to_checkpoint(&state, instance_id).await;
    }
    assert_eq!(status, "completed", "instance should reach completed");

    let node_statuses: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_all(&state.base.db)
            .await
            .expect("read node_runs");
    let by_id: std::collections::HashMap<_, _> = node_statuses.into_iter().collect();
    assert_eq!(by_id.get("t").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("c").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("a").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("b").map(String::as_str), Some("succeeded"));
    assert_eq!(
        by_id.get("dead").map(String::as_str),
        Some("skipped"),
        "the untaken condition branch must be skipped, not left pending"
    );
}

#[tokio::test]
async fn wait_node_pause_resume_round_trip() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "wait-round-trip-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "waiting");

    let wait_row_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workflow_trigger_index WHERE role = 'wait' AND instance_id = $1)",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("check wait row");
    assert!(
        wait_row_exists,
        "a wait row must exist while the instance is waiting"
    );

    // resume_at is 1 hour out — not due yet; sweep must be a no-op.
    sweep_expecting_unresolved(&state, instance_id, "resume_at is still an hour out").await;

    // Force it due, then sweep for real.
    sqlx::query("UPDATE workflow_trigger_index SET resume_at = NOW() - interval '1 second' WHERE instance_id = $1")
        .bind(instance_id)
        .execute(&state.base.db)
        .await
        .expect("force resume_at into the past");
    sweep_expecting_resolved(&state, instance_id).await;

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "completed");

    let wait_row_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workflow_trigger_index WHERE role = 'wait' AND instance_id = $1)",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("check wait row gone");
    assert!(
        !wait_row_exists,
        "the wait row must be deleted once resumed"
    );
}

#[tokio::test]
async fn cache_hit_reuses_prior_output_hash_for_identical_condition_input() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "c", "type": "condition", "config": {"op": "truthy"}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "c", "to_port": "value"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "cache-hit-test", graph).await;

    let i1 = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!(true),
    )
    .await
    .expect("start instance 1");
    run_to_checkpoint(&state, i1).await;

    let hash1: Option<String> = sqlx::query_scalar(
        "SELECT output_hash FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'c'",
    )
    .bind(i1)
    .fetch_one(&state.base.db)
    .await
    .expect("hash1");
    assert!(
        hash1.is_some(),
        "a cacheable node type must record an output_hash"
    );

    // Poison instance 1's stored output: `truthy(true)` really evaluated to
    // `true`, but we overwrite the DURABLE record of that output to `false`
    // without touching `output_hash` (which depends only on node/config/
    // input, never the output value — see `scheduler::output_hash`).
    // `output_hash` staying byte-identical after this is itself proof the
    // hash doesn't leak the output — if it did, this poisoning would change
    // it and the test below would trivially fail to find a "match" at all.
    sqlx::query("UPDATE workflow_instance SET node_data = jsonb_set(node_data, '{c}', 'false'::jsonb) WHERE id = $1")
        .bind(i1)
        .execute(&state.base.db)
        .await
        .expect("poison instance 1's cached output");

    // Instance 2 has the IDENTICAL input (same node type/config/resolved
    // value), so it must hash-match instance 1's node_run and hit the
    // cache — proven by it returning the POISONED `false`, which fresh
    // evaluation of `truthy(true)` would never produce on its own. This is
    // what actually distinguishes "the cache was read" from "the node just
    // happened to compute the same correct answer twice."
    let i2 = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!(true),
    )
    .await
    .expect("start instance 2");
    run_to_checkpoint(&state, i2).await;

    let hash2: Option<String> = sqlx::query_scalar(
        "SELECT output_hash FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'c'",
    )
    .bind(i2)
    .fetch_one(&state.base.db)
    .await
    .expect("hash2");
    assert_eq!(
        hash1, hash2,
        "identical inputs must produce the same cache key"
    );

    let i2_output: serde_json::Value =
        sqlx::query_scalar("SELECT node_data -> 'c' FROM workflow_instance WHERE id = $1")
            .bind(i2)
            .fetch_one(&state.base.db)
            .await
            .expect("i2 output");
    assert_eq!(
        i2_output,
        json!(false),
        "instance 2 must reuse instance 1's (poisoned) cached output, not recompute its own"
    );

    // The branch decision must also come from the cached (poisoned) value,
    // not fresh evaluation — a `false` cached value takes the "false" port.
    let i2_node_runs: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(i2)
            .fetch_all(&state.base.db)
            .await
            .expect("i2 node_runs");
    assert_eq!(
        i2_node_runs.len(),
        2,
        "only trigger + condition, no downstream nodes in this graph"
    );
    let i2_status: String =
        sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
            .bind(i2)
            .fetch_one(&state.base.db)
            .await
            .expect("i2 status");
    assert_eq!(i2_status, "completed");
}

#[tokio::test]
async fn retry_reaches_succeeded_after_configured_attempts() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    // update_record with no wired record_id/data on a nonexistent entity —
    // guaranteed to fail every attempt (deterministic), proving attempt_count
    // accumulates and the instance still terminates (failed) rather than
    // looping forever, bounded by max_attempts. `retry_delay_seconds: 0`
    // keeps the backoff wait immediately due so this test doesn't sleep.
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "u", "type": "update_record", "config": {
                "entity": "no_such_entity_workflow_retry_test", "max_attempts": 3,
                "retry_delay_seconds": 0
            }}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "u", "to_port": "record_id"},
            {"from_node": "t", "from_port": "out", "to_node": "u", "to_port": "data"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "retry-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({"id": Uuid::now_v7()}),
    )
    .await
    .expect("start instance");

    // Each failed attempt now checkpoints as a real backoff wait (F095) —
    // drain it the same way `wait_node_pause_resume_round_trip` does.
    let mut status = run_to_checkpoint(&state, instance_id).await;
    for _ in 0..10 {
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep retry backoff");
        status = run_to_checkpoint(&state, instance_id).await;
    }
    assert_eq!(status, "failed");

    let attempt_count: i32 = sqlx::query_scalar(
        "SELECT attempt_count FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'u'",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("attempt_count");
    assert_eq!(
        attempt_count, 3,
        "must retry up to max_attempts before failing"
    );
}

#[tokio::test]
async fn cancel_racing_a_stale_checkpoint_wins_via_row_version() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    let version_id = publish_workflow(&state.base.db, "cancel-race-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");
    run_to_checkpoint(&state, instance_id).await;

    // Simulate a concurrent cancel by bumping row_version out from under a
    // stale in-memory pass — commit_checkpoint's own row_version CAS must
    // reject a checkpoint write against a row it no longer matches.
    sqlx::query("UPDATE workflow_instance SET status = 'cancelled', row_version = row_version + 1 WHERE id = $1")
        .bind(instance_id)
        .execute(&state.base.db)
        .await
        .expect("simulate concurrent cancel");

    // A resume attempt racing the cancel must not resurrect the instance.
    sqlx::query("UPDATE workflow_trigger_index SET resume_at = NOW() - interval '1 second' WHERE instance_id = $1")
        .bind(instance_id)
        .execute(&state.base.db)
        .await
        .ok();
    let _ = attome_workflow::sla_sweep::sweep(&state).await;
    attome_workflow::scheduler::execute_instance(&state, instance_id)
        .await
        .expect("execute_instance after cancel must not error");

    let status: String = sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read status");
    assert_eq!(
        status, "cancelled",
        "a concurrent cancel must not be clobbered by a stale checkpoint"
    );
}

#[tokio::test]
async fn sub_workflow_resumes_parent_when_child_completes() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let child_graph = json!({
        "nodes": [
            {"id": "ct", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "cw", "type": "wait", "config": {"delay_seconds": -1}}
        ],
        "edges": [{"from_node": "ct", "from_port": "out", "to_node": "cw", "to_port": "in"}]
    });
    let child_version_id =
        publish_workflow(&state.base.db, "sub-workflow-child-test", child_graph).await;
    let child_logicalname: String = sqlx::query_scalar(
        "SELECT d.logicalname FROM workflow_definition d \
         JOIN workflow_definition_version v ON v.definition_id = d.id WHERE v.id = $1",
    )
    .bind(child_version_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read child logicalname");

    let parent_graph = json!({
        "nodes": [
            {"id": "pt", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "sw", "type": "sub_workflow", "config": {"definition_logicalname": child_logicalname}}
        ],
        "edges": [{"from_node": "pt", "from_port": "out", "to_node": "sw", "to_port": "input"}]
    });
    let parent_version_id =
        publish_workflow(&state.base.db, "sub-workflow-parent-test", parent_graph).await;

    let parent_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        parent_version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start parent instance");

    let parent_status = run_to_checkpoint(&state, parent_id).await;
    assert_eq!(
        parent_status, "waiting",
        "parent must pause at its sub_workflow node"
    );

    let child_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM workflow_instance WHERE context ->> 'parent_instance_id' = $1",
    )
    .bind(parent_id.to_string())
    .fetch_one(&state.base.db)
    .await
    .expect("find child instance started by the sub_workflow node");

    // Child's own Wait node is already due — sweep resumes it, then it completes.
    let child_status = run_to_checkpoint(&state, child_id).await;
    assert_eq!(child_status, "waiting");
    attome_workflow::sla_sweep::sweep(&state)
        .await
        .expect("sweep child wait");
    let child_status = run_to_checkpoint(&state, child_id).await;
    assert_eq!(child_status, "completed");

    // The child's own terminal checkpoint already resumed the parent's
    // sub_workflow node_run and enqueued EngineJob::WorkflowExecute for it
    // (scheduler::resume_parent_after_sub_workflow) — draining that "queue"
    // here is just calling execute_instance again, same as everywhere else
    // in this test file.
    let parent_status = run_to_checkpoint(&state, parent_id).await;
    assert_eq!(
        parent_status, "completed",
        "parent must resume and complete once its child does"
    );

    let sw_status: String = sqlx::query_scalar(
        "SELECT status FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'sw'",
    )
    .bind(parent_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read sub_workflow node_run status");
    assert_eq!(sw_status, "succeeded");
}

#[tokio::test]
async fn approval_round_trip_through_base_approval() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "ap", "type": "approval", "config": {"ttl_hours": 1}},
            {"id": "on_approved", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "on_rejected", "type": "wait", "config": {"delay_seconds": -1}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "ap", "to_port": "payload"},
            {"from_node": "ap", "from_port": "approved", "to_node": "on_approved", "to_port": "in"},
            {"from_node": "ap", "from_port": "rejected", "to_node": "on_rejected", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "approval-round-trip-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");
    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "waiting");

    let request_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'ap' ->> 'approval_request_id')::uuid \
         FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read approval_request_id from node_data");

    // Sweep before a decision exists — must be a no-op, not an error.
    sweep_expecting_unresolved(&state, instance_id, "no decision exists yet").await;

    let approver_id = seed_user(&state.base.db).await;
    attome_approval::decide(
        &state.base.db,
        request_id,
        approver_id,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("approve the request");

    sweep_expecting_resolved(&state, instance_id).await;

    // `on_approved` is itself a due Wait node — one more sweep drains it.
    let mut status = run_to_checkpoint(&state, instance_id).await;
    for _ in 0..10 {
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep on_approved wait");
        status = run_to_checkpoint(&state, instance_id).await;
    }
    assert_eq!(status, "completed");

    let decision: String = sqlx::query_scalar(
        "SELECT node_data -> 'ap' ->> 'decision' FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read recorded decision");
    assert_eq!(decision, "approved");

    let node_statuses: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_all(&state.base.db)
            .await
            .expect("read node_runs");
    let by_id: std::collections::HashMap<_, _> = node_statuses.into_iter().collect();
    assert_eq!(
        by_id.get("on_approved").map(String::as_str),
        Some("succeeded"),
        "the taken (approved) branch must run"
    );
    assert_eq!(
        by_id.get("on_rejected").map(String::as_str),
        Some("skipped"),
        "the untaken (rejected) branch must be skipped, not left pending"
    );
}

/// P-audit-item-17: the happy-path test above only proves the `approved`
/// port fires. This proves the workflow layer routes a `Decision::Reject`
/// to the `rejected` port instead — a genuinely new assertion, not a
/// duplicate of `attome-approval`'s own `decide_invariants.rs` (which proves
/// `decide()` itself accepts/records a Reject, not that the workflow graph
/// takes the correct branch afterward).
#[tokio::test]
async fn approval_rejected_decision_takes_the_rejected_port() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "ap", "type": "approval", "config": {"ttl_hours": 1}},
            {"id": "on_approved", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "on_rejected", "type": "wait", "config": {"delay_seconds": -1}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "ap", "to_port": "payload"},
            {"from_node": "ap", "from_port": "approved", "to_node": "on_approved", "to_port": "in"},
            {"from_node": "ap", "from_port": "rejected", "to_node": "on_rejected", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "approval-rejected-port-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");
    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "waiting");

    let request_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'ap' ->> 'approval_request_id')::uuid \
         FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read approval_request_id from node_data");

    let approver_id = seed_user(&state.base.db).await;
    attome_approval::decide(
        &state.base.db,
        request_id,
        approver_id,
        attome_approval::Decision::Reject,
        0,
    )
    .await
    .expect("reject the request");

    sweep_expecting_resolved(&state, instance_id).await;

    // `on_rejected` is itself a due Wait node — one more sweep drains it.
    let mut status = run_to_checkpoint(&state, instance_id).await;
    for _ in 0..10 {
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep on_rejected wait");
        status = run_to_checkpoint(&state, instance_id).await;
    }
    assert_eq!(status, "completed");

    let decision: String = sqlx::query_scalar(
        "SELECT node_data -> 'ap' ->> 'decision' FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read recorded decision");
    assert_eq!(decision, "rejected");

    let node_statuses: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_all(&state.base.db)
            .await
            .expect("read node_runs");
    let by_id: std::collections::HashMap<_, _> = node_statuses.into_iter().collect();
    assert_eq!(
        by_id.get("on_rejected").map(String::as_str),
        Some("succeeded"),
        "the taken (rejected) branch must run"
    );
    assert_eq!(
        by_id.get("on_approved").map(String::as_str),
        Some("skipped"),
        "the untaken (approved) branch must be skipped, not left pending"
    );
}

/// P-audit-item-17: `attome-approval`'s own `decide_invariants.rs` already
/// proves `decide()` rejects self-approval with `Forbidden` in isolation.
/// This proves the consequence AT the workflow layer: an unauthorized
/// decide() attempt must never be mistaken for "no decision yet" — the
/// instance must stay exactly `waiting`, the next sweep must see the
/// request as still pending (not resume anything), and no node_run may
/// silently record a decision that was actually rejected.
#[tokio::test]
async fn self_approval_is_forbidden_and_the_instance_stays_waiting() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "ap", "type": "approval", "config": {"ttl_hours": 1}},
            {"id": "on_approved", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "on_rejected", "type": "wait", "config": {"delay_seconds": -1}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "ap", "to_port": "payload"},
            {"from_node": "ap", "from_port": "approved", "to_node": "on_approved", "to_port": "in"},
            {"from_node": "ap", "from_port": "rejected", "to_node": "on_rejected", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(
        &state.base.db,
        "approval-self-approve-forbidden-test",
        graph,
    )
    .await;

    // started_by becomes attome_approval's `requested_by` (execute_approval
    // passes `instance.started_by` — see scheduler.rs).
    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");
    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "waiting");

    let request_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'ap' ->> 'approval_request_id')::uuid \
         FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read approval_request_id from node_data");

    // Same user who started the instance tries to approve their own request.
    let err = attome_approval::decide(
        &state.base.db,
        request_id,
        user_id,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect_err("self-approval must be rejected");
    assert!(matches!(err, attome_types::AppError::Forbidden));

    sweep_expecting_unresolved(
        &state,
        instance_id,
        "no decision was ever recorded — the sweep must not resume anything",
    )
    .await;

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(
        status, "waiting",
        "the instance must stay waiting — a Forbidden decide() attempt is not a decision"
    );

    let request_status: String =
        sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
            .bind(request_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read approval request status");
    assert_eq!(request_status, "pending");
}

/// §4.4 mechanism 1 (Create/Update Record's durable idempotency key):
/// simulates a crash between the entity INSERT + idempotency-record
/// completion committing (its own transaction, already durable) and the
/// workflow's own checkpoint committing (a separate, later transaction) —
/// exactly the window the mechanism exists to close. Directly resets the
/// instance/node_run state to "as if the checkpoint never landed" rather
/// than actually killing the process, since that's the only observable
/// difference a real crash there would leave behind.
#[tokio::test]
async fn create_record_replay_after_checkpoint_crash_does_not_duplicate() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        "wf_idem_test_entity",
        "Workflow Idempotency Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "name",
        "Name",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision name attribute");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("build registry"),
    );

    // `wf_idem_test_entity`'s physical table (via `ensure_entity`) persists
    // across test runs against the same throwaway database — count the
    // delta this test itself causes, not an absolute row count, so earlier
    // runs' leftover rows can never make this test flaky.
    let count = |db: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wf_idem_test_entity")
            .fetch_one(&db)
            .await
            .expect("count rows")
    };
    let baseline_count = count(state.base.db.clone()).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "cr", "type": "create_record", "config": {"entity": "wf_idem_test_entity"}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "cr", "to_port": "data"}]
    });
    let version_id =
        publish_workflow(&state.base.db, "create-record-idempotency-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({"name": "hello"}),
    )
    .await
    .expect("start instance");

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "completed");

    let row_count = count(state.base.db.clone()).await;
    assert_eq!(
        row_count,
        baseline_count + 1,
        "exactly one new record must exist after the real run"
    );

    let record_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'cr' ->> 'id')::uuid FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read the created record's id");

    // Simulate the crash: the checkpoint transaction (node_run row +
    // instance.node_data/status) never committed, even though the entity
    // INSERT + idempotency completion already did (separate, earlier
    // transaction). node_data resets to exactly what instance-creation
    // wrote (the trigger's own entry only, per `start_instance_internal`) —
    // NOT an empty object, which would also erase the trigger's already-
    // durable output and change `cr`'s resolved input/body_hash, hiding the
    // real crash-replay scenario behind a spurious "different request".
    sqlx::query("DELETE FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'cr'")
        .bind(instance_id)
        .execute(&state.base.db)
        .await
        .expect("delete node_run to simulate a pre-checkpoint crash");
    sqlx::query(
        "UPDATE workflow_instance \
         SET status = 'running', node_data = jsonb_build_object('t', context), completed_at = NULL \
         WHERE id = $1",
    )
    .bind(instance_id)
    .execute(&state.base.db)
    .await
    .expect("reset instance to running to simulate a pre-checkpoint crash");

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "completed", "the replayed pass must still complete");

    let row_count = count(state.base.db.clone()).await;
    assert_eq!(
        row_count,
        baseline_count + 1,
        "the replay must not create a second record"
    );

    let replayed_record_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'cr' ->> 'id')::uuid FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read the replayed record id");
    assert_eq!(
        replayed_record_id, record_id,
        "the replay must return the same record id"
    );
}

/// P-workflow-engine §5 step 6 follow-up (D-267 addendum): the entity-event
/// outbox dispatch that closes the "entity create/update auto-start" gap.
/// Inserts directly into `entity_change_event` (the exact row
/// `entity_mutation::create_one`/`update_one` write in production — that
/// write path is attome-api's own concern, not re-tested here) so this test
/// exercises `entity_trigger::dispatch_pending`'s own claim/match/start
/// logic in isolation.
#[tokio::test]
async fn entity_trigger_dispatch_starts_a_matching_instance_exactly_once() {
    let state = skip_if_no_db!(test_state().await);

    // Unique per run — a persistent throwaway database keeps every earlier
    // run's published trigger_index rows around, so a fixed entity name
    // would let an old run's entry also match this run's outbox event.
    let entity_logicalname = format!("wf_entity_trigger_test_entity_{}", Uuid::now_v7().simple());
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {
                "trigger_type": "create", "entity_logicalname": entity_logicalname
            }},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    publish_workflow(&state.base.db, "entity-trigger-dispatch-test", graph).await;

    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO entity_change_event (entity_logicalname, record_id, operation) \
         VALUES ($1, $2, 'create')",
    )
    .bind(&entity_logicalname)
    .bind(record_id)
    .execute(&state.base.db)
    .await
    .expect("insert outbox row");

    // The claim under test is per-record, so assert it per-record rather
    // than on `dispatch_pending`'s global return value — see
    // `dispatch_until_started` for why even `>= 1` on that count is not
    // hermetic under the parallel runner (F-006/TODO-008(c)).
    let started = dispatch_until_started(&state, record_id).await;
    assert_eq!(
        started, 1,
        "exactly one instance must start for the matching entry trigger"
    );

    let (instance_id, started_by): (Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT id, started_by FROM workflow_instance WHERE correlation_entity_id = $1",
    )
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("find the started instance");
    assert!(
        started_by.is_some(),
        "an entity-triggered instance must have a system started_by"
    );

    // `dispatch_pending` only enqueues `WorkflowExecute` (same as every
    // other start path) — no worker drains it in this test, so run the
    // first pass explicitly, same convention every other test here uses.
    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(
        status, "waiting",
        "the instance must run its Wait node and checkpoint"
    );

    let processed: bool = sqlx::query_scalar(
        "SELECT processed_at IS NOT NULL FROM entity_change_event WHERE record_id = $1",
    )
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("check outbox row processed");
    assert!(processed, "the claimed outbox row must be marked processed");

    // A second dispatch must not re-claim the same (already-processed) row.
    // Asserted per-record for the same reason as the first dispatch above: a
    // global `== 0` would also be claiming nothing else in the database has a
    // pending outbox row, which is not this test's business.
    attome_workflow::entity_trigger::dispatch_pending(&state)
        .await
        .expect("second dispatch pending events");
    assert_eq!(
        instances_for_record(&state, record_id).await,
        1,
        "an already-processed outbox row must never start a second instance"
    );
}

/// Closes the "WaitForEvent nodes never resume" gap: `entity_trigger::
/// dispatch_pending` must also drain `role='wait', match_type='entity_event'`
/// trigger_index rows, not just `role='entry'` ones.
#[tokio::test]
async fn wait_for_event_resumes_via_entity_trigger_dispatch() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    // Unique per run — see entity_trigger_dispatch_starts_a_matching_instance_
    // exactly_once's comment on why a fixed name isn't safe against a
    // persistent throwaway database's earlier-run leftovers.
    let entity_logicalname = format!("wf_wait_for_event_test_entity_{}", Uuid::now_v7().simple());
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "wfe", "type": "wait_for_event", "config": {
                "entity_logicalname": entity_logicalname
            }}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "wfe", "to_port": "in"}]
    });
    let version_id = publish_workflow(&state.base.db, "wait-for-event-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "waiting");

    let wait_row_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workflow_trigger_index \
         WHERE role = 'wait' AND match_type = 'entity_event' AND instance_id = $1)",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("check wait row");
    assert!(
        wait_row_exists,
        "a wait row must exist while the instance waits for an entity event"
    );

    // An event for a DIFFERENT entity must not resume it.
    let unrelated_record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO entity_change_event (entity_logicalname, record_id, operation) \
         VALUES ('some_other_entity', $1, 'create')",
    )
    .bind(unrelated_record_id)
    .execute(&state.base.db)
    .await
    .expect("insert unrelated outbox row");
    attome_workflow::entity_trigger::dispatch_pending(&state)
        .await
        .expect("dispatch unrelated event");
    let status_still_waiting: String =
        sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read status");
    assert_eq!(
        status_still_waiting, "waiting",
        "an unrelated entity event must not resume the wait"
    );

    // The matching event resumes it.
    let matching_record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO entity_change_event (entity_logicalname, record_id, operation) \
         VALUES ($1, $2, 'create')",
    )
    .bind(&entity_logicalname)
    .bind(matching_record_id)
    .execute(&state.base.db)
    .await
    .expect("insert matching outbox row");
    // Global count again (see the entry-trigger test above) — what this test
    // owns is that ITS waiting instance resumed, which the run-to-completion
    // and the drained `role='wait'` row below both prove.
    dispatch_until_resumed(&state, instance_id).await;

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "completed");

    let wait_row_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workflow_trigger_index \
         WHERE role = 'wait' AND instance_id = $1)",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("check wait row gone");
    assert!(!wait_row_exists);
}

/// Instances `version_id` started for `record_id` — scoped to one published
/// version so another run's or another test's triggers on the same entity
/// never count.
async fn instances_for(state: &EngineState, version_id: Uuid, record_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_instance \
         WHERE definition_version_id = $1 AND correlation_entity_id = $2",
    )
    .bind(version_id)
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("count instances for this version and record")
}

async fn insert_change_event(state: &EngineState, entity: &str, record_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO entity_change_event (entity_logicalname, record_id, operation) \
         VALUES ($1, $2, 'create') RETURNING id",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("insert outbox row")
}

/// M06 W1 acceptance (plan §4.1, G1). The old destructive claim marked the
/// whole batch processed before starting anything, so an error on event 2
/// lost events 2 and 3 for good. Here the fault fires on event 2 AFTER its
/// instance start committed but BEFORE the cursor advance — the exact window
/// a crash would hit. The re-run must re-read event 2 (and start nothing new
/// for it: migration 0501's unique index + ON CONFLICT DO NOTHING) and then
/// start event 3. Deterministic under the suite's documented
/// `--test-threads=1`; the intermediate assertions would race a sibling
/// test's dispatcher under the parallel runner.
#[tokio::test]
async fn a_dispatch_crash_mid_batch_starts_every_instance_exactly_once() {
    let state = skip_if_no_db!(test_state().await);

    let entity = format!("wf_crash_mid_batch_entity_{}", Uuid::now_v7().simple());
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {
                "trigger_type": "create", "entity_logicalname": entity
            }},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    let version_id = publish_workflow(&state.base.db, "crash-mid-batch-test", graph).await;

    let records = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
    let mut event_ids = Vec::new();
    for record_id in records {
        event_ids.push(insert_change_event(&state, &entity, record_id).await);
    }
    let poisoned = event_ids[1];
    let fault = move |event: &attome_core::change_feed::ChangeEvent| {
        if event.id == poisoned {
            Err(attome_types::AppError::internal(
                "injected crash after start",
            ))
        } else {
            Ok(())
        }
    };

    // Our three events become readable once the feed's visibility horizon
    // passes them; poll until the faulted run reaches event 2 and fails.
    let mut failed = false;
    for _ in 0..DISPATCH_POLL_PASSES {
        if attome_workflow::entity_trigger::dispatch_pending_with_fault(&state, Some(&fault))
            .await
            .is_err()
        {
            failed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(failed, "the injected fault on event 2 must abort the run");
    assert_eq!(instances_for(&state, version_id, records[0]).await, 1);
    assert_eq!(
        instances_for(&state, version_id, records[1]).await,
        1,
        "event 2's start committed before the fault"
    );
    assert_eq!(
        instances_for(&state, version_id, records[2]).await,
        0,
        "the run stopped at event 2; event 3 is still pending"
    );
    let event2_stamped: bool = sqlx::query_scalar(
        "SELECT processed_at IS NOT NULL FROM entity_change_event WHERE id = $1",
    )
    .bind(poisoned)
    .fetch_one(&state.base.db)
    .await
    .expect("read event 2");
    assert!(
        !event2_stamped,
        "a failed event must not be marked processed"
    );

    // Re-run without the fault: event 2 is re-read and event 3 starts.
    for _ in 0..DISPATCH_POLL_PASSES {
        attome_workflow::entity_trigger::dispatch_pending(&state)
            .await
            .expect("re-run dispatch");
        if instances_for(&state, version_id, records[2]).await > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    for (i, record_id) in records.iter().enumerate() {
        assert_eq!(
            instances_for(&state, version_id, *record_id).await,
            1,
            "event {} must start exactly one instance",
            i + 1
        );
    }
    let unstamped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event \
         WHERE id = ANY($1) AND processed_at IS NULL",
    )
    .bind(&event_ids)
    .fetch_one(&state.base.db)
    .await
    .expect("count unstamped events");
    assert_eq!(
        unstamped, 0,
        "every event is marked processed after the re-run"
    );
    assert_eq!(
        failure_row(&state, poisoned).await,
        None,
        "an event that failed once and then went through leaves no failure row"
    );

    // And a further run starts nothing more.
    attome_workflow::entity_trigger::dispatch_pending(&state)
        .await
        .expect("third dispatch");
    for record_id in records {
        assert_eq!(instances_for(&state, version_id, record_id).await, 1);
    }
}

/// `(attempts, dead-lettered?)` of `event_id`'s `workflow_trigger_failure`
/// row (migration 0510), `None` when there is none.
async fn failure_row(state: &EngineState, event_id: Uuid) -> Option<(i32, bool)> {
    sqlx::query_as::<_, (i32, bool)>(
        "SELECT attempts, dead_lettered_at IS NOT NULL \
         FROM workflow_trigger_failure WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_optional(&state.base.db)
    .await
    .expect("read failure row")
}

/// P0 0.9's open item: a permanently failing event used to hold the
/// `attome-workflow/entry` feed forever. It is now retried until it has failed
/// `MAX_ATTEMPTS` times over at least `DEAD_LETTER_AFTER_SECS`, then
/// dead-lettered and skipped, and the events behind it start. Both bounds
/// must hold: many quick failures alone (an outage) dead-letter nothing.
/// Deterministic under the suite's documented `--test-threads=1`.
#[tokio::test]
async fn a_permanently_failing_event_is_dead_lettered_and_the_feed_moves_on() {
    let state = skip_if_no_db!(test_state().await);

    let entity = format!("wf_dead_letter_entity_{}", Uuid::now_v7().simple());
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {
                "trigger_type": "create", "entity_logicalname": entity
            }},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    let version_id = publish_workflow(&state.base.db, "dead-letter-test", graph).await;

    let records = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
    let mut event_ids = Vec::new();
    for record_id in records {
        event_ids.push(insert_change_event(&state, &entity, record_id).await);
    }
    let poisoned = event_ids[1];
    let fault = move |event: &attome_core::change_feed::ChangeEvent| {
        if event.id == poisoned {
            Err(attome_types::AppError::internal(
                "injected permanent failure",
            ))
        } else {
            Ok(())
        }
    };

    // First failure: wait for the feed's visibility horizon to reach event 2.
    let mut failed = false;
    for _ in 0..DISPATCH_POLL_PASSES {
        if attome_workflow::entity_trigger::dispatch_pending_with_fault(&state, Some(&fault))
            .await
            .is_err()
        {
            failed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(failed, "event 2 must fail");
    assert_eq!(failure_row(&state, poisoned).await, Some((1, false)));

    // A breaker failure is the system's, not the event's: held, not counted.
    let overloaded = move |event: &attome_core::change_feed::ChangeEvent| {
        if event.id == poisoned {
            Err(attome_types::AppError::Overloaded("test_breaker"))
        } else {
            Ok(())
        }
    };
    assert!(
        attome_workflow::entity_trigger::dispatch_pending_with_fault(&state, Some(&overloaded))
            .await
            .is_err(),
        "an overloaded event still holds the feed"
    );
    assert_eq!(
        failure_row(&state, poisoned).await,
        Some((1, false)),
        "a transient failure is not an attempt"
    );

    // Past the attempt bound but not the age bound: still held, not skipped.
    for _ in 1..attome_workflow::entity_trigger::MAX_ATTEMPTS + 1 {
        assert!(
            attome_workflow::entity_trigger::dispatch_pending_with_fault(&state, Some(&fault))
                .await
                .is_err(),
            "a young failure holds the feed"
        );
    }
    let (attempts, dead) = failure_row(&state, poisoned).await.expect("failure row");
    assert!(attempts > attome_workflow::entity_trigger::MAX_ATTEMPTS);
    assert!(!dead, "quick repeated failures alone never dead-letter");
    assert_eq!(instances_for(&state, version_id, records[2]).await, 0);

    // Age the failure past the time bound; the next failure dead-letters it.
    sqlx::query(
        "UPDATE workflow_trigger_failure \
         SET first_failed_at = now() - make_interval(secs => $2) WHERE event_id = $1",
    )
    .bind(poisoned)
    .bind((attome_workflow::entity_trigger::DEAD_LETTER_AFTER_SECS + 60) as f64)
    .execute(&state.base.db)
    .await
    .expect("age the failure");
    attome_workflow::entity_trigger::dispatch_pending_with_fault(&state, Some(&fault))
        .await
        .expect("a dead-lettered event no longer fails the run");

    let (_, dead) = failure_row(&state, poisoned).await.expect("failure row");
    assert!(dead, "event 2 is dead-lettered");
    for record_id in records {
        assert_eq!(
            instances_for(&state, version_id, record_id).await,
            1,
            "event 3 starts once event 2 is out of the way"
        );
    }
    let unstamped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event \
         WHERE id = ANY($1) AND processed_at IS NULL",
    )
    .bind(&event_ids)
    .fetch_one(&state.base.db)
    .await
    .expect("count unstamped events");
    assert_eq!(unstamped, 0, "the dead letter is stamped with the rest");

    // The dead letter is never re-read, and its row stays for the operator.
    let before = failure_row(&state, poisoned).await;
    attome_workflow::entity_trigger::dispatch_pending_with_fault(&state, Some(&fault))
        .await
        .expect("later runs pass the dead letter by");
    assert_eq!(failure_row(&state, poisoned).await, before);
}

/// Writes a dead letter straight into `workflow_trigger_failure`, as the
/// dispatcher would after giving up on an event for `record_id`.
async fn insert_dead_letter(state: &EngineState, entity: &str, record_id: Uuid) -> Uuid {
    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workflow_trigger_failure \
             (event_id, entity_logicalname, record_id, operation, attempts, last_error, \
              dead_lettered_at) \
         VALUES ($1, $2, $3, 'create', 5, 'injected', now())",
    )
    .bind(event_id)
    .bind(entity)
    .bind(record_id)
    .execute(&state.base.db)
    .await
    .expect("insert dead letter");
    event_id
}

/// Replay starts what the dead-lettered event should have started, exactly
/// once, and removes the dead letter; discard removes one without dispatching.
/// Both answer `NotFound` for a dead letter that is gone.
#[tokio::test]
async fn a_dead_letter_replays_its_missed_start_once_and_can_be_discarded() {
    let state = skip_if_no_db!(test_state().await);
    let actor = seed_user(&state.base.db).await;

    let entity = format!("wf_dead_letter_replay_entity_{}", Uuid::now_v7().simple());
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {
                "trigger_type": "create", "entity_logicalname": entity
            }},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    let version_id = publish_workflow(&state.base.db, "dead-letter-replay-test", graph).await;

    let record_id = Uuid::now_v7();
    let event_id = insert_dead_letter(&state, &entity, record_id).await;
    assert_eq!(instances_for(&state, version_id, record_id).await, 0);

    let dispatched = attome_workflow::dead_letter_admin::replay(&state, event_id, actor)
        .await
        .expect("replay the dead letter");
    assert_eq!(dispatched, 1, "the missed start runs");
    assert_eq!(instances_for(&state, version_id, record_id).await, 1);
    assert_eq!(
        failure_row(&state, event_id).await,
        None,
        "replay removes it"
    );
    assert!(matches!(
        attome_workflow::dead_letter_admin::replay(&state, event_id, actor).await,
        Err(attome_types::AppError::NotFound)
    ));

    // A replay of the same event, had the row survived, starts nothing twice.
    let again = insert_dead_letter(&state, &entity, record_id).await;
    sqlx::query("UPDATE workflow_trigger_failure SET event_id = $2 WHERE event_id = $1")
        .bind(again)
        .bind(event_id)
        .execute(&state.base.db)
        .await
        .expect("reuse the replayed event id");
    assert_eq!(
        attome_workflow::dead_letter_admin::replay(&state, event_id, actor)
            .await
            .expect("second replay"),
        0
    );
    assert_eq!(instances_for(&state, version_id, record_id).await, 1);

    let other = Uuid::now_v7();
    let discarded = insert_dead_letter(&state, &entity, other).await;
    attome_workflow::dead_letter_admin::discard(&state, discarded, actor)
        .await
        .expect("discard the dead letter");
    assert_eq!(failure_row(&state, discarded).await, None);
    assert_eq!(
        instances_for(&state, version_id, other).await,
        0,
        "discard dispatches nothing"
    );
    assert!(matches!(
        attome_workflow::dead_letter_admin::discard(&state, discarded, actor).await,
        Err(attome_types::AppError::NotFound)
    ));
}

/// Provisions `wf_trigger_cond_entity (name text)` and reloads the registry,
/// so a trigger expression over `name` compiles and the record loads.
async fn provision_condition_entity(state: &EngineState) {
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        "wf_trigger_cond_entity",
        "Workflow Trigger Condition Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "name",
        "Name",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision name attribute");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("build registry"),
    );
}

/// M06 plan §4.2 / G3: an entry trigger's attome-rules `expression` is
/// evaluated against the record's current state before a start. A record
/// for which it is false starts nothing; one for which it is true starts
/// exactly one instance.
#[tokio::test]
async fn entry_trigger_expression_gates_the_start() {
    let state = skip_if_no_db!(test_state().await);
    provision_condition_entity(&state).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {
                "trigger_type": "create",
                "entity_logicalname": "wf_trigger_cond_entity",
                "expression": "name == \"go\""
            }},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    let version_id = publish_workflow(&state.base.db, "entry-expression-test", graph).await;
    attome_workflow::entity_trigger::validate_entry_expressions(&state, version_id, &parsed)
        .await
        .expect("a valid expression passes the publish-time check");

    let stop = Uuid::now_v7();
    let go = Uuid::now_v7();
    for (id, name) in [(stop, "stop"), (go, "go")] {
        sqlx::query("INSERT INTO wf_trigger_cond_entity (id, name) VALUES ($1, $2)")
            .bind(id)
            .bind(name)
            .execute(&state.base.db)
            .await
            .expect("insert test record");
    }
    // `stop`'s event is written first, so once `go` has started, `stop` has
    // certainly been evaluated.
    insert_change_event(&state, "wf_trigger_cond_entity", stop).await;
    insert_change_event(&state, "wf_trigger_cond_entity", go).await;

    for _ in 0..DISPATCH_POLL_PASSES {
        attome_workflow::entity_trigger::dispatch_pending(&state)
            .await
            .expect("dispatch");
        if instances_for(&state, version_id, go).await > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        instances_for(&state, version_id, go).await,
        1,
        "a true expression starts exactly one instance"
    );
    assert_eq!(
        instances_for(&state, version_id, stop).await,
        0,
        "a false expression starts no instance"
    );
}

/// Plan §4.2: an expression that does not compile against the entity is
/// rejected at publish with the node id; the same expression reaching
/// dispatch anyway (a hand-built index row) fails closed — no start.
#[tokio::test]
async fn entry_trigger_expression_that_does_not_compile_is_rejected_and_fails_closed() {
    let state = skip_if_no_db!(test_state().await);
    provision_condition_entity(&state).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {
                "trigger_type": "create",
                "entity_logicalname": "wf_trigger_cond_entity",
                "expression": "no_such_field == 1"
            }},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}]
    });
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    // `publish_workflow` bypasses the admin handler, so this also stands in
    // for the index row a pre-check publish could have left behind.
    let version_id = publish_workflow(&state.base.db, "bad-expression-test", graph).await;
    let err =
        attome_workflow::entity_trigger::validate_entry_expressions(&state, version_id, &parsed)
            .await
            .expect_err("an unknown field must be rejected at publish");
    assert!(
        matches!(&err, attome_types::AppError::Validation(msg) if msg.contains("trigger node \"t\"")),
        "the rejection is a 422 naming the node: {err:?}"
    );

    let record = Uuid::now_v7();
    sqlx::query("INSERT INTO wf_trigger_cond_entity (id, name) VALUES ($1, 'x')")
        .bind(record)
        .execute(&state.base.db)
        .await
        .expect("insert test record");
    let event_id = insert_change_event(&state, "wf_trigger_cond_entity", record).await;
    let mut processed = false;
    for _ in 0..DISPATCH_POLL_PASSES {
        attome_workflow::entity_trigger::dispatch_pending(&state)
            .await
            .expect("dispatch must not error on a broken expression");
        let stamped: bool = sqlx::query_scalar(
            "SELECT processed_at IS NOT NULL FROM entity_change_event WHERE id = $1",
        )
        .bind(event_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read event");
        if stamped {
            processed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(processed, "the event must have been dispatched");
    assert_eq!(
        instances_for(&state, version_id, record).await,
        0,
        "a trigger whose expression does not compile starts nothing"
    );
}

/// Closes half of the "sub-workflow recursion" gap: a definition whose
/// sub_workflow node points at itself must be rejected before it can ever
/// run. `graph::tests::self_referencing_sub_workflow_is_rejected` (a pure
/// unit test) covers the check's own logic in isolation; this integration
/// test proves the exact real-database logicalname a definition would carry
/// round-trips into the same rejection — the thing an HTTP-layer test would
/// otherwise be needed for.
#[tokio::test]
async fn sub_workflow_self_reference_is_rejected_using_a_real_definitions_own_logicalname() {
    let state = skip_if_no_db!(test_state().await);

    let logicalname = format!("sub-workflow-self-ref-test-{}", Uuid::now_v7());
    let definition_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .fetch_one(&state.base.db)
    .await
    .expect("insert definition");

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "sw", "type": "sub_workflow", "config": {"definition_logicalname": logicalname}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "sw", "to_port": "input"}]
    });

    let own_logicalname: String =
        sqlx::query_scalar("SELECT logicalname FROM workflow_definition WHERE id = $1")
            .bind(definition_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read own logicalname");
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    attome_workflow::graph::validate(&parsed).expect("single-graph validation passes on its own");

    let result =
        attome_workflow::graph::reject_self_referencing_sub_workflow(&parsed, &own_logicalname);
    assert!(
        result.is_err(),
        "the actual publish-time check must reject this self-reference"
    );
}

/// Closes the other half of the "sub-workflow recursion" gap: a chain of
/// DIFFERENT definitions (which the publish-time self-reference check
/// cannot see) is bounded by a runtime depth cap. Simulates "this instance
/// is already deeply nested" directly via `context.workflow_depth` rather
/// than actually walking `MAX_SUB_WORKFLOW_DEPTH` real parent/child
/// instances — this asserts the guard condition itself, which is what
/// actually prevents unbounded instance creation regardless of how many
/// definitions the real cycle spans.
#[tokio::test]
async fn sub_workflow_depth_cap_fails_instead_of_recursing_forever() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "sw", "type": "sub_workflow", "config": {"definition_logicalname": "does-not-need-to-exist"}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "sw", "to_port": "input"}]
    });
    let version_id = publish_workflow(&state.base.db, "sub-workflow-depth-cap-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");

    // Simulate "already at the cap" — the depth check runs before the
    // target-definition lookup, so it fires regardless of whether
    // "does-not-need-to-exist" is real.
    sqlx::query(
        "UPDATE workflow_instance SET context = '{\"workflow_depth\": 20}'::jsonb WHERE id = $1",
    )
    .bind(instance_id)
    .execute(&state.base.db)
    .await
    .expect("simulate max depth");

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "failed");

    let last_error: Option<String> = sqlx::query_scalar(
        "SELECT last_error FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'sw'",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read last_error");
    assert!(
        last_error.unwrap_or_default().contains("maximum depth"),
        "the failure must be attributed to the depth cap, not some other error"
    );
}

/// Publishes a graph WITHOUT `graph::validate`, standing in for the only way
/// an unknown node type reaches the scheduler in production: a version
/// published by a build whose registry knew the type (since removed), or a
/// row edited outside the publish path. `validate` rejects it at publish
/// time today — that was never the gap; the gap was what the scheduler did
/// once the row was there anyway (B20).
async fn publish_workflow_unvalidated(
    db: &sqlx::PgPool,
    logicalname: &str,
    graph: serde_json::Value,
) -> Uuid {
    let logicalname = format!("{logicalname}-{}", Uuid::now_v7());
    let definition_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .fetch_one(db)
    .await
    .expect("insert definition");

    let version_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition_version (definition_id, version_number, graph, status) \
         VALUES ($1, 1, $2, 'published') RETURNING id",
    )
    .bind(definition_id)
    .bind(&graph)
    .fetch_one(db)
    .await
    .expect("insert published version");

    // Entry rows only look at Trigger nodes, so an unknown sibling type is
    // no obstacle to registering the manual trigger.
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    let mut tx = db.begin().await.expect("begin tx");
    attome_workflow::trigger_index::rebuild_entry_rows(&mut tx, version_id, &parsed)
        .await
        .expect("rebuild entry rows");
    tx.commit().await.expect("commit");

    version_id
}

/// B20: a node whose type this build's registry does not know fails the
/// instance with a stored reason on its node_run, through the same arm every
/// other node failure takes — the pass returns `Ok`, and a redelivery is a
/// clean no-op. It used to be an `expect` on `NodeType::parse` (a panic in
/// the apalis worker task) and, before even reaching that, a node
/// `ready_nodes` silently never returned, so the instance failed through the
/// "fixpoint with unresolved nodes" branch with no node_run row at all.
#[tokio::test]
async fn unknown_node_type_fails_the_instance_with_a_stored_reason_instead_of_panicking() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "x", "type": "teleport_record", "config": {}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "x", "to_port": "in"}]
    });
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    assert!(
        attome_workflow::graph::validate(&parsed).is_err(),
        "publish-time validation still rejects the type; this test is about the row \
         getting past it"
    );
    let version_id =
        publish_workflow_unvalidated(&state.base.db, "unknown-node-type-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");

    attome_workflow::scheduler::execute_instance(&state, instance_id)
        .await
        .expect("the failure is the instance's, not the scheduler's: the pass returns Ok");

    let status: String = sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read instance status");
    assert_eq!(status, "failed");

    let (node_status, last_error): (String, Option<String>) = sqlx::query_as(
        "SELECT status, last_error FROM workflow_node_run \
         WHERE instance_id = $1 AND node_id = 'x'",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("the unknown-type node has a node_run row of its own");
    assert_eq!(node_status, "failed");
    let reason = last_error.expect("a stored reason on the node_run");
    assert!(
        reason.contains("teleport_record"),
        "last_error must name the unknown type, got {reason:?}"
    );

    // The scheduler continues: a redelivery of the same job is a no-op.
    attome_workflow::scheduler::execute_instance(&state, instance_id)
        .await
        .expect("redelivery on a failed instance is a clean no-op");
    let status: String = sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read instance status");
    assert_eq!(status, "failed");
}

/// 3.14: two deliveries of one instance's pass overlapping in time execute
/// each node once. The webhook node is the observable — a local listener
/// counts hits and parks the first call until the test releases it, so the
/// second delivery provably arrives while the first pass is mid-
/// `execute_node`. Before `scheduler::ExecutionClaim`, both passes ran the
/// node (two webhook calls) and only the second checkpoint was discarded.
#[tokio::test]
async fn concurrent_passes_on_one_instance_execute_each_node_once() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    struct Gate {
        hits: AtomicUsize,
        hit: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    let gate = Arc::new(Gate {
        hits: AtomicUsize::new(0),
        hit: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });

    let handler_gate = gate.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move || {
            let gate = handler_gate.clone();
            async move {
                gate.hits.fetch_add(1, Ordering::SeqCst);
                gate.hit.notify_one();
                gate.release.notified().await;
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let url = format!("http://{}/hook", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve webhook listener");
    });

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "webhook", "config": {"url": url, "method": "POST"}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "body"}]
    });
    let version_id = publish_workflow(&state.base.db, "concurrent-pass-claim-test", graph).await;
    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");

    let first = {
        let state = state.clone();
        tokio::spawn(async move {
            attome_workflow::scheduler::execute_instance(&state, instance_id).await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), gate.hit.notified())
        .await
        .expect("the first pass reaches the webhook node");

    // Second delivery, while the first pass is parked inside execute_node.
    attome_workflow::scheduler::execute_instance(&state, instance_id)
        .await
        .expect("the second delivery skips; it does not error");
    assert_eq!(
        gate.hits.load(Ordering::SeqCst),
        1,
        "the second pass must not execute the webhook node"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read instance status");
    assert_eq!(status, "running", "nothing has checkpointed yet");

    gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(20), first)
        .await
        .expect("the first pass finishes once the webhook is released")
        .expect("first pass task joins")
        .expect("first pass returns Ok");

    assert_eq!(gate.hits.load(Ordering::SeqCst), 1);
    let (status, fired): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, fired_side_effects FROM workflow_instance WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read instance");
    assert_eq!(status, "completed");
    assert_eq!(fired, json!(["w"]));

    // Released claim: a later delivery is the ordinary terminal no-op, not a skip.
    attome_workflow::scheduler::execute_instance(&state, instance_id)
        .await
        .expect("a delivery after the claim is released is a no-op");
    assert_eq!(gate.hits.load(Ordering::SeqCst), 1);
}

// ── M06 checklist item 1: Split/Join ────────────────────────────────────────

/// `Join`'s default (`"all"`) mode over an explicit `Split` fan-out — the
/// happy path a graph author gets without setting `config.mode` at all.
/// `scheduler::join_split_tests` already covers the pure `ready_nodes`
/// arithmetic for every mode without a database; this proves the same thing
/// end to end through a real published graph and a real instance.
#[tokio::test]
async fn explicit_split_join_all_mode_waits_for_every_branch() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    // trigger -> split -> [a, b] (both due-immediately waits) -> join(all)
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "s", "type": "split", "config": {}},
            {"id": "a", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "b", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "j", "type": "join", "config": {"mode": "all"}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "s", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "a", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "b", "to_port": "in"},
            {"from_node": "a", "from_port": "out", "to_node": "j", "to_port": "in"},
            {"from_node": "b", "from_port": "out", "to_node": "j", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "split-join-all-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!(true),
    )
    .await
    .expect("start instance");

    let mut status = run_to_checkpoint(&state, instance_id).await;
    for _ in 0..10 {
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep");
        status = run_to_checkpoint(&state, instance_id).await;
    }
    assert_eq!(
        status, "completed",
        "both branches settle, so the all-mode join must fire and the instance must complete"
    );

    let node_statuses: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_all(&state.base.db)
            .await
            .expect("read node_runs");
    let by_id: std::collections::HashMap<_, _> = node_statuses.into_iter().collect();
    assert_eq!(by_id.get("s").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("a").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("b").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("j").map(String::as_str), Some("succeeded"));
}

/// `Join`'s `"any"` mode fires once the FIRST branch settles, without
/// waiting for a sibling branch that never resolves in this test
/// (`wait_for_event` with no matching entity event dispatched) — proving
/// the join does not degrade to the `"all"`/implicit-fan-in behavior. The
/// whole instance still cannot reach `completed` (every node must settle
/// for that), which is the documented scope simplification: an `"any"`
/// join firing early does not cancel its still-live sibling branches.
#[tokio::test]
async fn explicit_split_join_any_mode_fires_without_waiting_for_every_branch() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "s", "type": "split", "config": {}},
            {"id": "a", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "b", "type": "wait_for_event", "config": {}},
            {"id": "j", "type": "join", "config": {"mode": "any"}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "s", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "a", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "b", "to_port": "in"},
            {"from_node": "a", "from_port": "out", "to_node": "j", "to_port": "in"},
            {"from_node": "b", "from_port": "event", "to_node": "j", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "split-join-any-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!(true),
    )
    .await
    .expect("start instance");

    let mut status = run_to_checkpoint(&state, instance_id).await;
    // "a" is due immediately; sweeping resumes it, which is what lets the
    // any-mode join become ready without "b" (which never resolves here).
    for _ in 0..10 {
        let join_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'j'",
        )
        .bind(instance_id)
        .fetch_optional(&state.base.db)
        .await
        .expect("read join status");
        if join_status.as_deref() == Some("succeeded") {
            break;
        }
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep");
        status = run_to_checkpoint(&state, instance_id).await;
    }

    let node_statuses: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_all(&state.base.db)
            .await
            .expect("read node_runs");
    let by_id: std::collections::HashMap<_, _> = node_statuses.into_iter().collect();
    assert_eq!(by_id.get("a").map(String::as_str), Some("succeeded"));
    assert_eq!(
        by_id.get("j").map(String::as_str),
        Some("succeeded"),
        "any-mode join must fire once branch a settles, without waiting for b"
    );
    assert_eq!(
        by_id.get("b").map(String::as_str),
        Some("waiting"),
        "branch b has no external event in this test and must still be waiting"
    );

    let instance_status: String =
        sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read instance status");
    assert_eq!(
        instance_status, "waiting",
        "the instance stays waiting until every node settles, even though the join itself already fired"
    );
}

/// `n_of_m`: three branches, threshold 2 — must not fire after only one
/// settles, must fire once two have, without needing the third.
#[tokio::test]
async fn explicit_split_join_n_of_m_mode_fires_at_its_threshold() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "s", "type": "split", "config": {}},
            {"id": "a", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "b", "type": "wait", "config": {"delay_seconds": -1}},
            {"id": "c", "type": "wait_for_event", "config": {}},
            {"id": "j", "type": "join", "config": {"mode": "n_of_m", "n": 2}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "s", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "a", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "b", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "c", "to_port": "in"},
            {"from_node": "a", "from_port": "out", "to_node": "j", "to_port": "in"},
            {"from_node": "b", "from_port": "out", "to_node": "j", "to_port": "in"},
            {"from_node": "c", "from_port": "event", "to_node": "j", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "split-join-n-of-m-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!(true),
    )
    .await
    .expect("start instance");

    let mut status = run_to_checkpoint(&state, instance_id).await;
    for _ in 0..10 {
        let join_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'j'",
        )
        .bind(instance_id)
        .fetch_optional(&state.base.db)
        .await
        .expect("read join status");
        if join_status.as_deref() == Some("succeeded") {
            break;
        }
        if status != "waiting" {
            break;
        }
        attome_workflow::sla_sweep::sweep(&state)
            .await
            .expect("sweep");
        status = run_to_checkpoint(&state, instance_id).await;
    }

    let node_statuses: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1")
            .bind(instance_id)
            .fetch_all(&state.base.db)
            .await
            .expect("read node_runs");
    let by_id: std::collections::HashMap<_, _> = node_statuses.into_iter().collect();
    assert_eq!(by_id.get("a").map(String::as_str), Some("succeeded"));
    assert_eq!(by_id.get("b").map(String::as_str), Some("succeeded"));
    assert_eq!(
        by_id.get("j").map(String::as_str),
        Some("succeeded"),
        "n_of_m(2) join must fire once 2 of its 3 branches settle"
    );
    assert_eq!(
        by_id.get("c").map(String::as_str),
        Some("waiting"),
        "the third branch has no external event in this test and must still be waiting"
    );
}

/// A `Split` with no reachable `Join` is rejected at publish, before any
/// instance can ever be started from it (M06 checklist item 1).
#[tokio::test]
async fn split_with_no_reachable_join_is_rejected_at_publish() {
    let state = skip_if_no_db!(test_state().await);

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "s", "type": "split", "config": {}},
            {"id": "a", "type": "wait", "config": {}},
            {"id": "b", "type": "wait", "config": {}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "s", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "a", "to_port": "in"},
            {"from_node": "s", "from_port": "out", "to_node": "b", "to_port": "in"}
        ]
    });
    let logicalname = format!("split-no-join-test-{}", Uuid::now_v7());
    sqlx::query("INSERT INTO workflow_definition (logicalname, name, owner_layer) VALUES ($1, $1, 'project')")
        .bind(&logicalname)
        .execute(&state.base.db)
        .await
        .expect("insert definition");

    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    let err = attome_workflow::graph::validate(&parsed)
        .expect_err("a split with no reachable join must fail graph validation");
    assert!(
        err.0.contains("no reachable Join"),
        "unexpected validation error: {}",
        err.0
    );
}

// ── M06 checklist item 2: dry-run / simulate ────────────────────────────────

/// D-431's contract, proven directly: a simulate run over a graph carrying
/// every node type this plan names as needing dry-run treatment
/// (`create_record`, `webhook`, `approval`) must leave the database
/// completely untouched — no new workflow instance, no new node_run, and no
/// new row in the entity a live run would have created.
#[tokio::test]
async fn dry_run_simulate_writes_nothing_to_the_database() {
    let state = skip_if_no_db!(test_state().await);

    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        "wf_simulate_test_entity",
        "Workflow Simulate Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "name",
        "Name",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision name attribute");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("build registry"),
    );

    let entity_row_count = || {
        let db = state.base.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM wf_simulate_test_entity")
                .fetch_one(&db)
                .await
                .expect("count rows")
        }
    };
    let instance_count = || {
        let db = state.base.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflow_instance")
                .fetch_one(&db)
                .await
                .expect("count instances")
        }
    };
    let node_run_count = || {
        let db = state.base.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflow_node_run")
                .fetch_one(&db)
                .await
                .expect("count node_runs")
        }
    };

    let before_entity_rows = entity_row_count().await;
    let before_instances = instance_count().await;
    let before_node_runs = node_run_count().await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "cr", "type": "create_record", "config": {"entity": "wf_simulate_test_entity"}},
            {"id": "wh", "type": "webhook", "config": {"url": "https://example.invalid/hook", "method": "POST"}},
            {"id": "ap", "type": "approval", "config": {"action_type": "workflow.simulate-test"}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "cr", "to_port": "data"},
            {"from_node": "t", "from_port": "out", "to_node": "wh", "to_port": "body"},
            {"from_node": "t", "from_port": "out", "to_node": "ap", "to_port": "payload"}
        ]
    });
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    attome_workflow::graph::validate(&parsed).expect("graph validates");

    let (status, trace) = attome_workflow::simulate::run_simulation(
        &state,
        &parsed,
        json!({"name": "simulated"}),
        &std::collections::HashMap::new(),
    );

    assert_eq!(status, "completed", "trace: {trace:#?}");
    let by_id: std::collections::HashMap<_, _> =
        trace.into_iter().map(|t| (t.node_id.clone(), t)).collect();
    assert_eq!(by_id["cr"].status, "succeeded");
    assert!(
        by_id["cr"]
            .would_have
            .as_deref()
            .unwrap_or_default()
            .contains("would create"),
        "{:?}",
        by_id["cr"].would_have
    );
    assert_eq!(by_id["wh"].status, "succeeded");
    assert!(
        by_id["wh"]
            .would_have
            .as_deref()
            .unwrap_or_default()
            .contains("would send"),
        "{:?}",
        by_id["wh"].would_have
    );
    assert_eq!(by_id["ap"].status, "succeeded");
    assert_eq!(
        by_id["ap"].taken_port.as_deref(),
        Some("approved"),
        "no decision was supplied — must default to auto-approved"
    );

    assert_eq!(
        entity_row_count().await,
        before_entity_rows,
        "dry run must never insert into the target entity table"
    );
    assert_eq!(
        instance_count().await,
        before_instances,
        "dry run must never create a real workflow instance"
    );
    assert_eq!(
        node_run_count().await,
        before_node_runs,
        "dry run must never write a real node_run row"
    );
}

/// The `approval` node's decision is driven entirely by the caller-supplied
/// `approval_decisions` map — proves the `"rejected"` branch is reachable
/// too, not just the auto-approve default.
#[tokio::test]
async fn dry_run_simulate_honors_supplied_approval_decisions() {
    let state = skip_if_no_db!(test_state().await);

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "ap", "type": "approval", "config": {"action_type": "workflow.simulate-test"}},
            {"id": "approved_only", "type": "wait", "config": {}},
            {"id": "rejected_only", "type": "wait", "config": {}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "ap", "to_port": "payload"},
            {"from_node": "ap", "from_port": "approved", "to_node": "approved_only", "to_port": "in"},
            {"from_node": "ap", "from_port": "rejected", "to_node": "rejected_only", "to_port": "in"}
        ]
    });
    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    attome_workflow::graph::validate(&parsed).expect("graph validates");

    let mut decisions = std::collections::HashMap::new();
    decisions.insert("ap".to_string(), "rejected".to_string());

    let (status, trace) =
        attome_workflow::simulate::run_simulation(&state, &parsed, json!({}), &decisions);
    // Both surviving nodes are `Wait`s, which dry run treats as an instant
    // passthrough (not a suspension) — so with the supplied "rejected"
    // decision routing around the only other branch, every node in this
    // graph settles and the run reaches "completed".
    assert_eq!(status, "completed", "trace: {trace:#?}");
    let by_id: std::collections::HashMap<_, _> =
        trace.into_iter().map(|t| (t.node_id.clone(), t)).collect();
    assert_eq!(by_id["ap"].taken_port.as_deref(), Some("rejected"));
    assert_eq!(
        by_id["rejected_only"].status, "succeeded",
        "the taken port's downstream node must actually run"
    );
    assert_eq!(
        by_id["approved_only"].status, "skipped",
        "the untaken port's downstream node must be skipped, not left pending"
    );
}

/// M01 Core C-10's named DB proof: a record created by the workflow
/// scheduler's Create Record node is visible to its owner. Before this
/// item, `execute_entity_write` called `entity_mutation::create_one`
/// directly and never called `grant_creator_share` — the D-133 (2) implicit
/// `record_share` row a Team/BusinessUnit-scoped caller depends on
/// to see a record they don't otherwise hold organization-wide access to.
/// `instance.started_by` (`user_id` here) is exactly that caller: the
/// principal the workflow ran as, which is who a Create Record node's
/// output should belong to.
///
/// This drives the real scheduler (`start_instance_internal` +
/// `run_to_checkpoint`), not `create_one` directly — the point is to prove
/// the end-to-end wiring through `execute_entity_write` ->
/// `MutationRing::commit_mutation`, not the ring's own unit-tested behavior
/// (see `attome-records/tests/mutation_ring.rs` for that).
#[tokio::test]
async fn create_record_node_grants_the_creator_share_to_started_by() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        "wf_owner_visibility_test_entity",
        "Workflow Owner Visibility Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("build registry"),
    );

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "cr", "type": "create_record", "config": {"entity": "wf_owner_visibility_test_entity"}}
        ],
        "edges": [{"from_node": "t", "from_port": "out", "to_node": "cr", "to_port": "data"}]
    });
    let version_id =
        publish_workflow(&state.base.db, "create-record-owner-visibility-test", graph).await;

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance");

    let status = run_to_checkpoint(&state, instance_id).await;
    assert_eq!(status, "completed");

    let record_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'cr' ->> 'id')::uuid FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read the created record's id");

    let share_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record_share \
         WHERE record_id = $1 AND entity_ref = $2 AND principal_type = 0 \
           AND principal_id = $3 AND capability = 1",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .fetch_one(&state.base.db)
    .await
    .expect("query share row");

    assert_eq!(
        share_count, 1,
        "the workflow scheduler's Create Record node must grant \
         `instance.started_by` the same D-133 (2) creator-share row an \
         interactive create gets — before C-10 this was 0, and a \
         Team/BusinessUnit-scoped user could never see a record their own \
         workflow instance created"
    );

    // Also written unconditionally now that the ring owns this mutation's
    // audit event end to end — before C-10, `execute_entity_write` wrote
    // none at all for a Create/Update Record node.
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header \
         WHERE entity_name = 'wf_owner_visibility_test_entity' AND record_id = $1",
    )
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("query audit header row");
    assert_eq!(
        audit_count, 1,
        "the ring must also write the audit header this mutation never \
         got before C-10"
    );
}

/// Invariant I1 — the Create Record node is a third way into
/// `entity_mutation::create_one`, alongside the generic entity API and the
/// bundle record-set apply, so the audit-ledger guard has to hold for a
/// workflow too.
///
/// `seed_platform` already registers the three ledger entities, and the
/// registry is rebuilt below so `execute_entity_write` resolves them:
/// without that the node would fail with `unknown entity`, which is a
/// refusal for the wrong reason and would prove nothing about the guard.
/// That is why the assertions read the node's recorded error rather than
/// merely observing that the instance failed.
///
/// The ledger rows the engine itself legitimately writes are not affected:
/// every checkpoint audits its node-run transitions through
/// `attome_metadata::crud::insert`, the audit engine's own writer, which is
/// deliberately not behind this guard. Each count below is filtered to this
/// run's own marker, so those rows can never mask a leak.
#[tokio::test]
async fn workflow_create_record_is_refused_for_every_audit_ledger_entity() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("build registry"),
    );

    let marker = format!("ledger-guard-{}", Uuid::now_v7());

    let cases: [(&str, serde_json::Value, &str); 3] = [
        (
            "audit_header",
            json!({
                "category": 1,
                "operation": 1,
                "event_hash": marker.as_str(),
                "initiator": 1
            }),
            "SELECT COUNT(*) FROM audit_header WHERE event_hash = $1",
        ),
        (
            "audit_detail",
            // `audit_ref` is a required lookup; the guard runs before the
            // body is validated, so it never has to resolve.
            json!({
                "audit_ref": Uuid::now_v7().to_string(),
                "field_name": marker.as_str()
            }),
            "SELECT COUNT(*) FROM audit_detail WHERE field_name = $1",
        ),
        (
            "audit_snapshot",
            json!({
                "entity_name": marker.as_str(),
                "record_id": Uuid::now_v7().to_string(),
                "version": 1,
                "snapshot_json": "{}"
            }),
            "SELECT COUNT(*) FROM audit_snapshot WHERE entity_name = $1",
        ),
    ];

    for (entity, input, count_sql) in cases {
        let graph = json!({
            "nodes": [
                {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
                {"id": "cr", "type": "create_record", "config": {"entity": entity}}
            ],
            "edges": [{"from_node": "t", "from_port": "out", "to_node": "cr", "to_port": "data"}]
        });
        let version_id =
            publish_workflow(&state.base.db, "ledger-create-record-refused", graph).await;

        let instance_id = attome_workflow::instance_admin::start_instance_internal(
            &state,
            version_id,
            None,
            Some(user_id),
            None,
            input,
        )
        .await
        .expect("start instance");

        // `max_attempts` defaults to 1, so the node fails on its first
        // attempt rather than parking on a retry wait.
        let status = run_to_checkpoint(&state, instance_id).await;
        assert_eq!(
            status, "failed",
            "{entity}: the instance must fail rather than create a ledger row"
        );

        let last_error: Option<String> = sqlx::query_scalar(
            "SELECT last_error FROM workflow_node_run \
             WHERE instance_id = $1 AND node_id = 'cr'",
        )
        .bind(instance_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read the create_record node's recorded error");
        let last_error = last_error.unwrap_or_default();
        assert!(
            last_error.contains("forbidden"),
            "{entity}: the node must be refused by the ledger guard, got {last_error:?}"
        );
        assert!(
            !last_error.contains("unknown entity"),
            "{entity}: the entity must resolve — this failure is the registry, not the guard"
        );

        let count: i64 = sqlx::query_scalar(count_sql)
            .bind(marker.as_str())
            .fetch_one(&state.base.db)
            .await
            .expect("count ledger rows");
        assert_eq!(
            count, 0,
            "{entity}: the refused node must leave no ledger row behind"
        );
    }
}

// ---------------------------------------------------------------------------
// C5 (chatbot plan) — `workflow.start` through the `WorkflowStarter` seam
// ---------------------------------------------------------------------------

/// A one-node manual workflow, published; returns its generated logical name
/// (`publish_workflow` suffixes it) and the published version.
async fn publish_manual_workflow(db: &sqlx::PgPool) -> (String, Uuid) {
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "wait", "config": {"delay_seconds": -1}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(db, "c5-agent-start", graph).await;
    let logicalname: String = sqlx::query_scalar(
        "SELECT d.logicalname FROM workflow_definition d \
         JOIN workflow_definition_version v ON v.definition_id = d.id WHERE v.id = $1",
    )
    .bind(version_id)
    .fetch_one(db)
    .await
    .expect("read logicalname");
    (logicalname, version_id)
}

async fn instances_of_version(db: &sqlx::PgPool, version_id: Uuid) -> Vec<(Uuid, Option<Uuid>)> {
    sqlx::query_as("SELECT id, started_by FROM workflow_instance WHERE definition_version_id = $1")
        .bind(version_id)
        .fetch_all(db)
        .await
        .expect("list instances")
}

/// **The seam is the manual-start path.** `PublishedWorkflowStarter` starts
/// the published version and records the caller as `started_by`, exactly as
/// `POST /api/v1/workflow/instances` does — it is the same
/// `start_published_instance` — and refuses a name with no published, active
/// version rather than starting anything.
#[tokio::test]
async fn the_workflow_starter_seam_is_the_manual_start_path() {
    use attome_core::{WorkflowStartRequest, WorkflowStarter};

    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let (logicalname, version_id) = publish_manual_workflow(&state.base.db).await;

    let starter = attome_workflow::instance_admin::PublishedWorkflowStarter;
    let instance_id = starter
        .start(
            &state,
            WorkflowStartRequest {
                definition_logicalname: logicalname.clone(),
                started_by: user_id,
                correlation_entity_id: None,
                context: json!({}),
            },
        )
        .await
        .expect("start through the seam");
    assert_eq!(
        instances_of_version(&state.base.db, version_id).await,
        vec![(instance_id, Some(user_id))]
    );

    let err = starter
        .start(
            &state,
            WorkflowStartRequest {
                definition_logicalname: format!("{logicalname}-missing"),
                started_by: user_id,
                correlation_entity_id: None,
                context: json!({}),
            },
        )
        .await
        .expect_err("no published version");
    assert!(
        matches!(err, attome_types::AppError::Validation(_)),
        "{err:?}"
    );
}

/// **Row A-22 for `workflow.start`, against the real start path.** An
/// administrator's agent proposes it: approval requested, **no instance**. A
/// second person approves; the approved request executes through
/// `attome-ai`'s approved-execution path and the registered
/// `PublishedWorkflowStarter`: **exactly one** instance, started by the
/// human the agent acts for. (The confirm step before the approval is
/// covered in `attome-ai`'s `workflow_start.rs`; the start path is proven here.)
#[tokio::test]
async fn an_agent_workflow_start_waits_for_approval_then_starts_exactly_one_instance() {
    let mut state = skip_if_no_db!(test_state().await);
    state.workflow_starter = Some(std::sync::Arc::new(
        attome_workflow::instance_admin::PublishedWorkflowStarter,
    ));
    state
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    let db = state.base.db.clone();
    let owner = seed_user(&db).await;
    grant_system_admin(&db, owner).await;
    let (logicalname, version_id) = publish_manual_workflow(&db).await;

    let session = attome_ai::session::start(
        &db,
        &attome_audit::audit_service(&state),
        attome_ai::session::SessionStart {
            owner_user_id: owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session");
    let security = std::sync::Arc::new(
        attome_security::resolve_uncached(&db, owner)
            .await
            .expect("security"),
    );
    let mut ctx = attome_ai::turn::context_for(security, &session);
    ctx.idempotency_key = Some("wf-start-1".into());

    let outcome = attome_ai::execute::dispatch(
        &state,
        &attome_ai::registry::ActionRegistry::new(),
        &attome_ai::execute::Executors::new(),
        "workflow.start",
        &ctx,
        &attome_ai::gate::GateInputs {
            licensed: true,
            ai: &state.base.config.inference.ai,
            surface: None,
            external_effects_enabled: false,
        },
        &json!({"definition_logicalname": logicalname}),
    )
    .await
    .expect("dispatch");
    let attome_ai::execute::ActionOutcome::ApprovalRequired { approval_id } = outcome else {
        panic!("an agent's workflow.start requires approval, got {outcome:?}");
    };
    assert!(
        instances_of_version(&db, version_id).await.is_empty(),
        "no instance before the approval"
    );

    let approver = seed_user(&db).await;
    grant_system_admin(&db, approver).await;
    attome_approval::decide(
        &db,
        approval_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a second person approves");
    let request = attome_ai::approval::approved_payload(&db, approval_id)
        .await
        .expect("read")
        .expect("approved payload");
    let executed = attome_ai::execute::dispatch_approved_agent_action_under(
        &state,
        &request,
        Some(approval_id),
    )
    .await
    .expect("execute the approved start");
    let attome_ai::execute::ApprovedExecution::Executed(result) = executed else {
        panic!("the approved start runs, got {executed:?}");
    };

    let instances = instances_of_version(&db, version_id).await;
    assert_eq!(instances.len(), 1, "exactly one instance");
    assert_eq!(
        instances[0].1,
        Some(owner),
        "started by the human, not the agent"
    );
    assert_eq!(result["instance_id"], json!(instances[0].0));
}

async fn grant_system_admin(db: &sqlx::PgPool, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, 'system.admin', 'system.admin', 'test', true, NOW(), 'project') \
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("ensure system.admin");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = 'system.admin'",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(db)
    .await
    .expect("grant system.admin");
}

/// Plan 4.3 (C19) -- `start_instance_internal` previously wrote no audit
/// event at all for instance start, despite `x-audit` annotating both the
/// manual-start route and `scheduler::execute_sub_workflow`'s call site as
/// covered. Proves the fix: a human-started instance (`started_by =
/// Some(user_id)`) writes `Initiator::User` with that user as actor, and a
/// system-triggered one (`started_by = None`, the shape `execute_sub_workflow`
/// uses when a parent instance's own chain traces back to no human) writes
/// `Initiator::System` -- never a nil-actor `Initiator::User`, which would
/// misreport "a real user with no id" instead of "the system."
#[tokio::test]
async fn instance_start_attributes_to_the_real_starter_or_system() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;

    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}
        ]
    });
    let version_id =
        publish_workflow(&state.base.db, "instance-start-attribution-test", graph).await;

    async fn stored_attribution(db: &attome_db::DbPool, instance_id: Uuid) -> (i16, Uuid) {
        sqlx::query_as(
            "SELECT initiator, user_id FROM audit_header \
             WHERE entity_name = 'workflow_instance' AND record_id = $1",
        )
        .bind(instance_id)
        .fetch_one(db)
        .await
        .expect("fetch the instance-start audit header")
    }

    let human_instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        Some(user_id),
        None,
        json!({}),
    )
    .await
    .expect("start instance (human)");
    // Drains audit_ingest into audit_header when the running config
    // has chainer_enabled = true; a harmless no-op (nothing to drain) when
    // the sync path already wrote the header directly.
    drain_audit_chainer(&state.base.db).await;
    let (human_initiator, human_actor) =
        stored_attribution(&state.base.db, human_instance_id).await;
    assert_eq!(
        human_initiator,
        attome_audit::Initiator::User.as_i16(),
        "a human-started instance must attribute Initiator::User"
    );
    assert_eq!(human_actor, user_id);

    let system_instance_id = attome_workflow::instance_admin::start_instance_internal(
        &state,
        version_id,
        None,
        None,
        None,
        json!({}),
    )
    .await
    .expect("start instance (system)");
    drain_audit_chainer(&state.base.db).await;
    let (system_initiator, system_actor) =
        stored_attribution(&state.base.db, system_instance_id).await;
    assert_eq!(
        system_initiator,
        attome_audit::Initiator::System.as_i16(),
        "a system-triggered instance (no started_by) must attribute Initiator::System, \
         never Initiator::User with a nil actor"
    );
    assert_eq!(system_actor, Uuid::nil());
}

/// Runs the chainer until nothing is pending. One `run_once` drains at most
/// one batch per organization, and this binary shares one database across its
/// tests, so earlier tests' events can sit ahead of the ones being checked.
/// Bounded, and a chainer error fails the test rather than being swallowed.
async fn drain_audit_chainer(db: &attome_db::DbPool) {
    for _ in 0..100 {
        let drained = attome_audit::chainer::run_once(db, None, 500, None)
            .await
            .expect("audit chainer run");
        if drained.is_empty() {
            return;
        }
    }
    panic!("the audit chainer still had pending events after 100 runs");
}
