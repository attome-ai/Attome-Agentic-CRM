//! E8-T4: journey enrolment and the batched start against a real database —
//! one active run per person, the re-entry rule, the daily cap, the exit
//! condition ending a run before its next step, and 2,500 people started in
//! batches. Here rather than in `attome-marketing` because the enrolment
//! starts real runs: `attome-workflow` depends (through `attome-ai`) on
//! `attome-marketing`, so only this crate can hold both.
//!
//! Requires a live, throwaway Postgres (`DATABASE_URL`); skips loudly when
//! it is unset, except under `CI`. Fixture rows are direct SQL against the
//! throwaway database (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-workflow --test journey_enrol"
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
use attome_marketing::journey::{PersonRef, enrol};
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
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
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

/// `state` able to enrol: every module licensed, the workflow starter and
/// the journey guard registered, and the entity registry loaded for the
/// guard's conditions.
async fn journey_state() -> Option<EngineState> {
    let mut state = test_state().await?;
    let db = state.base.db.clone();
    for (name, fields) in [
        ("contact", &[("email", "text")][..]),
        (
            "marketing_journey",
            &[
                ("workflow_definition_logicalname", "text"),
                ("re_entry", "text"),
                ("cool_off_days", "number"),
                ("daily_entry_cap", "number"),
                ("exit_condition", "text"),
                ("goal_condition", "text"),
                ("goal_exits", "bool"),
                ("status", "text"),
            ][..],
        ),
    ] {
        let id = attome_metadata::provision::ensure_entity(&db, name, name, None, false)
            .await
            .expect("provision entity");
        for (field, field_type) in fields {
            attome_metadata::provision::ensure_attribute(
                &db, id, field, field, field_type, false, false, false, true, None, None,
            )
            .await
            .expect("provision attribute");
        }
    }
    state
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    state.workflow_starter = Some(std::sync::Arc::new(
        attome_workflow::instance_admin::PublishedWorkflowStarter,
    ));
    let guard: std::sync::Arc<dyn attome_core::workflow_step::WorkflowKindGuard> =
        std::sync::Arc::new(attome_marketing::journey::guard::JourneyGuard);
    state.workflow_kind_guards =
        std::sync::Arc::new(std::collections::HashMap::from([("journey", guard)]));
    state
        .entities
        .swap(attome_core::build_registry(&db).await.expect("registry"));
    Some(state)
}

/// A live journey: a published journey workflow (trigger, then an hour's
/// wait) and its settings record. Returns the settings record's id and the
/// workflow's logical name.
async fn journey(
    state: &EngineState,
    re_entry: &str,
    daily_cap: Option<i64>,
    exit_condition: Option<&str>,
) -> (Uuid, String) {
    let graph = json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 3600}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"}
        ]
    });
    let version_id = publish_workflow(&state.base.db, "journey-test", graph).await;
    let logicalname: String = sqlx::query_scalar(
        "UPDATE workflow_definition SET kind = 'journey' \
          WHERE id = (SELECT definition_id FROM workflow_definition_version WHERE id = $1) \
         RETURNING logicalname",
    )
    .bind(version_id)
    .fetch_one(&state.base.db)
    .await
    .expect("make the definition a journey");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_journey \
            (id, workflow_definition_logicalname, re_entry, daily_entry_cap, exit_condition, status) \
         VALUES ($1, $2, $3, $4, $5, 'live')",
    )
    .bind(id)
    .bind(&logicalname)
    .bind(re_entry)
    .bind(daily_cap)
    .bind(exit_condition)
    .execute(&state.base.db)
    .await
    .expect("insert journey settings");
    (id, logicalname)
}

async fn contact(state: &EngineState, email: &str) -> PersonRef {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO contact (id, email) VALUES ($1, $2)")
        .bind(id)
        .bind(email)
        .execute(&state.base.db)
        .await
        .expect("insert contact");
    PersonRef {
        id,
        entity: "contact".into(),
    }
}

async fn runs_of(state: &EngineState, logicalname: &str, person: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
          WHERE d.logicalname = $1 AND i.correlation_entity_id = $2",
    )
    .bind(logicalname)
    .bind(person)
    .fetch_one(&state.base.db)
    .await
    .expect("count runs")
}

#[tokio::test]
async fn one_active_run_per_person() {
    let state = skip_if_no_db!(journey_state().await);
    let (journey_id, logicalname) = journey(&state, "after_exit", None, None).await;
    let person = contact(&state, "once@test.invalid").await;

    let first = enrol(&state, journey_id, vec![person.clone()], "test", false)
        .await
        .expect("first enrolment");
    assert_eq!(first.enrolled, 1);
    let second = enrol(&state, journey_id, vec![person.clone()], "test", false)
        .await
        .expect("second enrolment");
    assert_eq!(second.enrolled, 0);
    assert_eq!(second.skipped_active, 1);
    assert_eq!(runs_of(&state, &logicalname, person.id).await, 1);
    let linked: Option<Uuid> = sqlx::query_scalar(
        "SELECT instance_id FROM marketing_journey_enrolment WHERE person_id = $1 AND status = 'active'",
    )
    .bind(person.id)
    .fetch_one(&state.base.db)
    .await
    .expect("read the enrolment");
    assert!(linked.is_some(), "the enrolment records its run");
}

#[tokio::test]
async fn re_entry_never_skips_returning_person() {
    let state = skip_if_no_db!(journey_state().await);
    let (journey_id, logicalname) = journey(&state, "never", None, None).await;
    let person = contact(&state, "returning@test.invalid").await;
    enrol(&state, journey_id, vec![person.clone()], "test", false)
        .await
        .expect("first enrolment");
    sqlx::query(
        "UPDATE marketing_journey_enrolment SET status = 'exited', ended_at = now() WHERE person_id = $1",
    )
    .bind(person.id)
    .execute(&state.base.db)
    .await
    .expect("end the run");

    let again = enrol(&state, journey_id, vec![person.clone()], "test", false)
        .await
        .expect("second enrolment");
    assert_eq!(again.enrolled, 0);
    assert_eq!(again.skipped_re_entry, 1);
    assert_eq!(runs_of(&state, &logicalname, person.id).await, 1);
}

#[tokio::test]
async fn daily_cap_limits_entries() {
    let state = skip_if_no_db!(journey_state().await);
    let (journey_id, _) = journey(&state, "after_exit", Some(2), None).await;
    let mut people = Vec::new();
    for n in 0..3 {
        people.push(contact(&state, &format!("cap{n}@test.invalid")).await);
    }
    let outcome = enrol(&state, journey_id, people, "test", false)
        .await
        .expect("enrol");
    assert_eq!(outcome.enrolled, 2);
    assert_eq!(outcome.skipped_cap, 1);
}

#[tokio::test]
async fn exit_condition_cancels_before_next_step() {
    let state = skip_if_no_db!(journey_state().await);
    let (journey_id, logicalname) = journey(
        &state,
        "after_exit",
        None,
        Some("email == \"leaving@test.invalid\""),
    )
    .await;
    let person = contact(&state, "leaving@test.invalid").await;
    enrol(&state, journey_id, vec![person.clone()], "test", false)
        .await
        .expect("enrol");
    let instance_id: Uuid = sqlx::query_scalar(
        "SELECT i.id FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
          WHERE d.logicalname = $1 AND i.correlation_entity_id = $2",
    )
    .bind(&logicalname)
    .bind(person.id)
    .fetch_one(&state.base.db)
    .await
    .expect("the run");

    assert_eq!(run_to_checkpoint(&state, instance_id).await, "cancelled");
    let (status, reason): (String, Option<String>) = sqlx::query_as(
        "SELECT status, end_reason FROM marketing_journey_enrolment WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read the enrolment");
    assert_eq!(status, "exited");
    assert_eq!(reason.as_deref(), Some("exit_condition"));
    let waited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_node_run WHERE instance_id = $1 AND node_id = 'w'",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("count wait runs");
    assert_eq!(waited, 0, "the next step never ran");
}

#[tokio::test]
async fn batch_of_2500_starts_2500_instances() {
    let state = skip_if_no_db!(journey_state().await);
    let (_, logicalname) = journey(&state, "after_exit", None, None).await;
    let items: Vec<(Uuid, serde_json::Value)> = (0..2_500)
        .map(|n| (Uuid::now_v7(), json!({ "n": n })))
        .collect();
    let started =
        attome_workflow::instance_admin::start_instances_batch(&state, &logicalname, None, items)
            .await
            .expect("batched start");
    assert_eq!(started.len(), 2_500);
    let (instances, entry_runs): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(DISTINCT i.id), COUNT(r.id) FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
           LEFT JOIN workflow_node_run r ON r.instance_id = i.id AND r.node_id = 't' \
          WHERE d.logicalname = $1",
    )
    .bind(&logicalname)
    .fetch_one(&state.base.db)
    .await
    .expect("count instances");
    assert_eq!(instances, 2_500);
    assert_eq!(entry_runs, 2_500);
}
