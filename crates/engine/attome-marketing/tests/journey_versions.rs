//! E8-T8: journey version moves against a real database — the preview
//! counts people per waiting node, `move_matching` moves only runs waiting
//! at a node the new version keeps (with everything upstream of it done),
//! and `finish_on_old` moves nobody.
//!
//! Workflow rows are direct SQL against this binary's throwaway database
//! (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test journey_versions"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_marketing::journey::versions::{self, VersionMode};
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use serde_json::{Value, json};
use uuid::Uuid;

fn test_config() -> AppConfig {
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
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 8, "timeout": 5.0
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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod", "jwt_issuer": "attome-test",
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
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_state() -> Option<EngineState> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config).await.expect("connect");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("redis");
    let coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("storage");
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        coordination,
        storage,
    );
    Some(EngineState::new(base))
}

fn graph(nodes: &[&str]) -> Value {
    let edges: Vec<Value> = nodes
        .windows(2)
        .map(|w| json!({"from_node": w[0], "from_port": "out", "to_node": w[1], "to_port": "in"}))
        .collect();
    json!({
        "nodes": nodes.iter().map(|n| json!({"id": n, "type": "x"})).collect::<Vec<_>>(),
        "edges": edges,
    })
}

/// A journey workflow with v1 (start -> email -> wait -> sms) and v2
/// (start -> email -> wait -> call: "sms" removed, "call" added).
async fn journey(state: &EngineState) -> (Uuid, Uuid, Uuid) {
    let db = &state.base.db;
    let definition = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workflow_definition (id, logicalname, name, owner_layer, kind) \
         VALUES ($1, $2, 'version test', 'customer', 'journey')",
    )
    .bind(definition)
    .bind(format!("journey_{}", definition.simple()))
    .execute(db)
    .await
    .expect("definition");
    let mut versions = Vec::new();
    for (number, nodes) in [
        (1, &["start", "email", "wait", "sms"][..]),
        (2, &["start", "email", "wait", "call"][..]),
    ] {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO workflow_definition_version (id, definition_id, version_number, graph, status) \
             VALUES ($1, $2, $3, $4, 'published')",
        )
        .bind(id)
        .bind(definition)
        .bind(number)
        .bind(graph(nodes))
        .execute(db)
        .await
        .expect("version");
        versions.push(id);
    }
    (definition, versions[0], versions[1])
}

/// A person on v1 with a run in `status`, waiting at `waiting` (if any)
/// after finishing `finished`.
async fn person(
    state: &EngineState,
    definition: Uuid,
    v1: Uuid,
    status: &str,
    finished: &[&str],
    waiting: Option<&str>,
) -> Uuid {
    let db = &state.base.db;
    let instance = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workflow_instance (id, definition_version_id, status) VALUES ($1, $2, $3)",
    )
    .bind(instance)
    .bind(v1)
    .bind(status)
    .execute(db)
    .await
    .expect("instance");
    for node in finished {
        sqlx::query(
            "INSERT INTO workflow_node_run (instance_id, node_id, status) VALUES ($1, $2, 'succeeded')",
        )
        .bind(instance)
        .bind(node)
        .execute(db)
        .await
        .expect("node run");
    }
    if let Some(node) = waiting {
        sqlx::query(
            "INSERT INTO workflow_node_run (instance_id, node_id, status) VALUES ($1, $2, 'waiting')",
        )
        .bind(instance)
        .bind(node)
        .execute(db)
        .await
        .expect("waiting node run");
    }
    sqlx::query(
        "INSERT INTO marketing_journey_enrolment \
            (definition_id, definition_version_id, person_id, person_entity, instance_id, status, entry_source) \
         VALUES ($1, $2, $3, 'contact', $4, 'active', 'api')",
    )
    .bind(definition)
    .bind(v1)
    .bind(Uuid::now_v7())
    .bind(instance)
    .execute(db)
    .await
    .expect("enrolment");
    instance
}

async fn version_of(state: &EngineState, instance: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as(
        "SELECT i.definition_version_id, e.definition_version_id FROM workflow_instance i \
           JOIN marketing_journey_enrolment e ON e.instance_id = i.id WHERE i.id = $1",
    )
    .bind(instance)
    .fetch_one(&state.base.db)
    .await
    .expect("versions")
}

async fn node_history(state: &EngineState, instance: Uuid) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT node_id, status FROM workflow_node_run WHERE instance_id = $1 ORDER BY node_id",
    )
    .bind(instance)
    .fetch_all(&state.base.db)
    .await
    .expect("node runs")
}

#[tokio::test]
async fn preview_counts_waiting_people() {
    let state = skip_if_no_db!(test_state().await);
    let (definition, v1, v2) = journey(&state).await;
    for _ in 0..2 {
        person(
            &state,
            definition,
            v1,
            "waiting",
            &["start", "email"],
            Some("wait"),
        )
        .await;
    }
    person(
        &state,
        definition,
        v1,
        "waiting",
        &["start", "email", "wait"],
        Some("sms"),
    )
    .await;
    // A running run is not counted: it is not waiting.
    person(&state, definition, v1, "running", &["start"], None).await;
    let preview = versions::preview(&state, definition, v2).await.unwrap();
    let rows: Vec<(String, i64, bool, i64)> = preview
        .into_iter()
        .map(|n| (n.node_id, n.waiting_count, n.exists_in_new, n.movable_count))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("sms".to_owned(), 1, false, 0),
            ("wait".to_owned(), 2, true, 2),
        ]
    );
}

#[tokio::test]
async fn move_matching_moves_only_matching_nodes() {
    let state = skip_if_no_db!(test_state().await);
    let (definition, v1, v2) = journey(&state).await;
    let at_wait = person(
        &state,
        definition,
        v1,
        "waiting",
        &["start", "email"],
        Some("wait"),
    )
    .await;
    let at_sms = person(
        &state,
        definition,
        v1,
        "waiting",
        &["start", "email", "wait"],
        Some("sms"),
    )
    .await;
    let running = person(&state, definition, v1, "running", &["start"], Some("email")).await;
    let history_before = node_history(&state, at_wait).await;
    let outcome = versions::move_to_version(
        &state,
        definition,
        v2,
        VersionMode::MoveMatching,
        Uuid::nil(),
    )
    .await
    .unwrap();
    assert_eq!((outcome.moved, outcome.kept), (1, 1));
    assert_eq!(version_of(&state, at_wait).await, (v2, v2));
    assert_eq!(
        version_of(&state, at_sms).await,
        (v1, v1),
        "sms is gone in v2"
    );
    assert_eq!(
        version_of(&state, running).await,
        (v1, v1),
        "a running run never moves"
    );
    assert_eq!(
        node_history(&state, at_wait).await,
        history_before,
        "history untouched"
    );
}

#[tokio::test]
async fn finish_on_old_moves_nobody() {
    let state = skip_if_no_db!(test_state().await);
    let (definition, v1, v2) = journey(&state).await;
    let at_wait = person(
        &state,
        definition,
        v1,
        "waiting",
        &["start", "email"],
        Some("wait"),
    )
    .await;
    let outcome = versions::move_to_version(
        &state,
        definition,
        v2,
        VersionMode::FinishOnOld,
        Uuid::nil(),
    )
    .await
    .unwrap();
    assert_eq!((outcome.moved, outcome.kept), (0, 1));
    assert_eq!(version_of(&state, at_wait).await, (v1, v1));
}
