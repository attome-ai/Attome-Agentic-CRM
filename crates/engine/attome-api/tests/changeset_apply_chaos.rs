//! AB9-T5 — changeset apply under a killed worker. An apply run commits one
//! step at a time and advances the ledger cursor after each
//! (`attome_api::changeset::apply`'s module doc), so a crash can leave a run
//! between two durable writes. This file stops a real run at each such
//! window through the test-only `apply::crash` points (the `test-support`
//! feature; a release build has none), then restarts it the way a new worker
//! does (the dead claim ages past the takeover timeout), and proves the end
//! state is whole: all three operations applied once and one `succeeded`
//! ledger row, never one or two.
//!
//! | window                         | durable state left behind                 | recovery under test               |
//! |--------------------------------|-------------------------------------------|-----------------------------------|
//! | a step committed, cursor not   | 2 of 3 written, `applying`, cursor 1      | takeover resumes at the cursor; the re-run step is unchanged |
//! | every step done, row not closed| 3 of 3 written, `applying`, cursor 3      | takeover runs no step and closes  |
//! | row closed, report not ready   | `succeeded`, report `building`            | nothing to redo; the report stays readable |
//!
//! The kill is a panic inside the spawned run (as `metadata_chaos.rs`
//! produces each crash's durable state directly): the future stops at that
//! await point and nothing after it runs. Requires a live Postgres
//! (`DATABASE_URL`) and Redis; skips loudly without them:
//!
//! ```powershell
//! cargo test -p attome-api --test changeset_apply_chaos
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test inspects and ages ledger state on a raw pool"
)]

use attome_api::EngineSystem;
use attome_api::changeset::apply::crash::{self, Window};
use attome_api::changeset::apply::{self, RunOutcome};
use attome_api::changeset::ledger::{self, ApplySource};
use attome_api::changeset::plan::{self, PlanContext};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use serde_json::{Value, json};
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(mode: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 30,
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
            "security": {{ "bootstrap_admin_email": null }},
            "approval": {{ "required_actions": [] }},
            "metadata": {{ "changesets": {{ "mode": "{mode}" }} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

#[derive(Clone)]
struct TestSystem {
    state: EngineState,
}

impl TestSystem {
    fn db(&self) -> DbPool {
        self.state.base.db.clone()
    }
}

/// An `EngineSystem` over `db` (every pool role on the one pool), every module
/// licensed.
async fn system_over(config: AppConfig, db: DbPool) -> TestSystem {
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
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    TestSystem {
        state: system.state().clone(),
    }
}

/// The migrated test database, `auto` mode (the applier never records).
async fn test_system() -> Option<TestSystem> {
    static SYSTEM: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();
    SYSTEM
        .get_or_init(|| async {
            let url = attome_testkit::migrated_db_url()?;
            let mut config = test_config("auto");
            point_config_at(&mut config, &url);
            let db = attome_db::create_pool(&config)
                .await
                .expect("connect DATABASE_URL");
            Some(system_over(config, db).await)
        })
        .await
        .clone()
}

fn suffix() -> String {
    Uuid::now_v7().simple().to_string()[20..].to_owned()
}

/// A closed `project` changeset of three independent operations (three
/// privileges, each its own step), with its checksum.
fn three_item_document(tag: &str) -> (Value, Vec<String>) {
    let keys: Vec<String> = ["one", "two", "three"]
        .iter()
        .map(|n| format!("ab9{tag}.{n}"))
        .collect();
    let operations: Vec<Value> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            json!({
                "seq": i + 1,
                "op": "ensure_privilege",
                "phase": "expand",
                "target": { "privilege": key },
                "args": { "definition": {
                    "key": key,
                    "name": format!("AB9 chaos {key}"),
                    "description": "Written by the changeset apply crash test.",
                } },
            })
        })
        .collect();
    let mut document = json!({
        "format": "attome-changeset/v1",
        "id": Uuid::now_v7().to_string(),
        "layer": "project",
        "scope": format!("ab9-chaos-{tag}"),
        "seq": 1,
        "name": "crash-windows",
        "title": "AB9-T5 crash windows",
        "requires": { "modules": ["core"], "platform": ">=0.1.0" },
        "author": "changeset_apply_chaos",
        "opened_at": "2026-10-29T00:00:00Z",
        "closed_at": "2026-10-29T00:00:00Z",
        "checksum": "",
        "operations": operations,
    });
    document["checksum"] = json!(
        attome_api::changeset::jcs::document_checksum(&document).expect("checksum the document")
    );
    (document, keys)
}

/// Plans, persists and queues `document`: its one expand ledger row.
async fn queue(state: &EngineState, document: &Value) -> Uuid {
    let ctx = PlanContext {
        source: ApplySource::Replay,
        requested_by: None,
        trusted: false,
        accept_clashes: true,
    };
    let mut planned = plan::plan(state, std::slice::from_ref(document), ctx)
        .await
        .expect("plan the changeset");
    assert!(
        planned.plan.applicable,
        "the plan is blocked: {}",
        serde_json::to_string_pretty(&planned.plan).unwrap_or_default()
    );
    let mut tx = attome_db::tx::begin(&state.base.db).await.expect("begin");
    plan::persist(&mut tx, &mut planned, ctx)
        .await
        .expect("persist the plan");
    let ids = planned.plan.apply_ids.clone();
    assert_eq!(ids.len(), 1, "one expand row");
    ledger::mark_queued(&mut tx, &ids, None, None)
        .await
        .expect("queue");
    attome_db::tx::commit(tx).await.expect("commit");
    ids[0]
}

/// Runs the row in its own task with `window` armed, and proves the run
/// died there (the task panicked: a killed worker).
async fn crash_at(state: &EngineState, apply_id: Uuid, window: Window) {
    crash::arm(apply_id, window);
    let state = state.clone();
    let joined = tokio::spawn(async move { apply::run_one(&state, apply_id).await }).await;
    let error = joined.expect_err("the run must stop at its crash window");
    assert!(error.is_panic(), "the run ended by a panic at {window:?}");
}

/// What a crash left on disk, as the ledger and the metadata see it.
#[derive(Debug, PartialEq, Eq)]
struct Durable {
    status: String,
    cursor: i32,
    privileges: i64,
}

async fn durable(db: &DbPool, apply_id: Uuid, keys: &[String]) -> Durable {
    let (status, cursor): (String, i32) =
        sqlx::query_as("SELECT status, cursor FROM changeset_apply WHERE id = $1")
            .bind(apply_id)
            .fetch_one(db)
            .await
            .expect("read the ledger row");
    let privileges: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privilege WHERE key = ANY($1)")
        .bind(keys)
        .fetch_one(db)
        .await
        .expect("count the privileges");
    Durable {
        status,
        cursor,
        privileges,
    }
}

/// The restart: the dead worker's claim goes quiet for longer than the
/// takeover timeout (the clock is moved, not waited out).
async fn age_claim(db: &DbPool, apply_id: Uuid) {
    sqlx::query(
        "UPDATE changeset_apply \
            SET claimed_at = NOW() - INTERVAL '31 minutes', \
                updated_at = NOW() - INTERVAL '31 minutes' \
          WHERE id = $1",
    )
    .bind(apply_id)
    .execute(db)
    .await
    .expect("age the dead claim");
}

/// The end state every window must reach: all three operations applied
/// exactly once, one `succeeded` ledger row for the changeset, cursor at the
/// end. Never one or two.
async fn assert_whole(db: &DbPool, document: &Value, apply_id: Uuid, keys: &[String]) {
    assert_eq!(
        durable(db, apply_id, keys).await,
        Durable {
            status: "succeeded".into(),
            cursor: 3,
            privileges: 3,
        }
    );
    let changeset_id = Uuid::parse_str(document["id"].as_str().expect("id")).expect("uuid");
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM changeset_apply WHERE changeset_id = $1")
            .bind(changeset_id)
            .fetch_one(db)
            .await
            .expect("count ledger rows");
    assert_eq!(rows, 1, "one ledger row for the changeset");
    // Each privilege once, active.
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT key) FROM privilege WHERE key = ANY($1) AND is_active",
    )
    .bind(keys)
    .fetch_one(db)
    .await
    .expect("count active privileges");
    assert_eq!(active, 3);
}

#[test]
fn apply_crash_mid_items() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.db();
        let (document, keys) = three_item_document(&suffix());
        let apply_id = queue(&system.state, &document).await;

        // The second operation committed; its cursor advance never ran.
        crash_at(&system.state, apply_id, Window::AfterStep(1)).await;
        assert_eq!(
            durable(&db, apply_id, &keys).await,
            Durable {
                status: "applying".into(),
                cursor: 1,
                privileges: 2,
            },
            "two committed operations and a cursor one behind them"
        );

        // A live claim is not taken over.
        assert_eq!(
            apply::run_one(&system.state, apply_id).await.expect("run"),
            RunOutcome::NotClaimed
        );

        age_claim(&db, apply_id).await;
        match apply::run_one(&system.state, apply_id)
            .await
            .expect("resume")
        {
            RunOutcome::Applied(summary) => {
                // Resumed at the cursor: the second operation re-runs as
                // unchanged, the third writes.
                assert_eq!(summary.steps, 2);
                assert_eq!(summary.written, 1);
                assert_eq!(summary.unchanged, 1);
            }
            RunOutcome::NotClaimed => panic!("the dead claim was not taken over"),
        }
        assert_whole(&db, &document, apply_id, &keys).await;
    })
}

#[test]
fn apply_crash_before_ledger() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.db();
        let (document, keys) = three_item_document(&suffix());
        let apply_id = queue(&system.state, &document).await;

        // Every operation committed and advanced; the row was never closed.
        crash_at(&system.state, apply_id, Window::BeforeLedger).await;
        assert_eq!(
            durable(&db, apply_id, &keys).await,
            Durable {
                status: "applying".into(),
                cursor: 3,
                privileges: 3,
            }
        );

        age_claim(&db, apply_id).await;
        match apply::run_one(&system.state, apply_id)
            .await
            .expect("resume")
        {
            RunOutcome::Applied(summary) => {
                assert_eq!(summary.steps, 0, "nothing left to run past the cursor");
                assert_eq!(summary.written, 0);
            }
            RunOutcome::NotClaimed => panic!("the dead claim was not taken over"),
        }
        assert_whole(&db, &document, apply_id, &keys).await;
    })
}

#[test]
fn apply_crash_before_report() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.db();
        let (document, keys) = three_item_document(&suffix());
        let apply_id = queue(&system.state, &document).await;

        // The ledger row closed; the report was never marked ready.
        crash_at(&system.state, apply_id, Window::BeforeReport).await;
        assert_whole(&db, &document, apply_id, &keys).await;

        // A redelivered run finds nothing to do and writes nothing again.
        assert_eq!(
            apply::run_one(&system.state, apply_id)
                .await
                .expect("rerun"),
            RunOutcome::NotClaimed
        );
        assert_whole(&db, &document, apply_id, &keys).await;

        // The report stays `building` and readable (apply.rs's report
        // contract); it never blocks the apply.
        let status: Option<String> = sqlx::query_scalar(
            "SELECT r.status FROM changeset_apply a \
               JOIN release_report r ON r.id = a.report_ref WHERE a.id = $1",
        )
        .bind(apply_id)
        .fetch_optional(&db)
        .await
        .expect("read the report");
        assert_eq!(status.as_deref(), Some("building"));
    })
}
