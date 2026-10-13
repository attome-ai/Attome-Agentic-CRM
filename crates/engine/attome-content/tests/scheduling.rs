//! M56 Content Management Phase 1 (D-436) — the scheduled-publish sweep,
//! exercised directly against `attome_content::scheduling::
//! sweep_scheduled_transitions`, same shape as `attome-workflow/tests/
//! execution.rs`/`attome-dashboard/tests/metric.rs` (call the engine function
//! directly rather than standing up a full authenticated HTTP request).
//!
//! Requires a live Postgres (`DATABASE_URL`) with migration `0230_content_
//! page_scheduled_publishing.sql` applied, plus a reachable Redis and
//! storage endpoint (`AppState::new` wants both, even though this sweep
//! never touches either) — skips (loudly) when `DATABASE_URL` is unset,
//! except under `CI`, per the P1.8 testing-baseline convention.
//!
//! No `attome_audit::seed` call is needed here (unlike `attome-workflow/tests/
//! execution.rs`'s `seed_platform`): `audit.chainer_enabled` defaults to
//! `true` (D-316) and this suite's config never overrides it, so
//! `AuditService::write_in_tx` takes the `audit_ingest` capture path —
//! a plain parameterized insert into a migration-owned infra table, not
//! `attome_metadata::crud`, so it never resolves `audit_header` through
//! entity metadata the way the header-writing path would.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-content --test scheduling -- --test-threads=1
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

use attome_config::AppConfig;
use attome_content::model::{Block, BlockKind};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use serde_json::json;
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
                "host": "localhost", "port": 5555, "dbname": "unused",
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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
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
            "cors": {{ "allowed_origins": ["http://allowed.test"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

// `std::env::set_var` is unsafe in edition 2024 (concurrent mutation from
// another thread is a real data race) — same `ENV_LOCK` shape `attome-workflow/
// tests/execution.rs` uses, serializing this suite's own writes against each
// other regardless of `--test-threads`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
    // reads this var while this guard is held.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
    }
    let config = test_config();
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
    Some(EngineState::new(base))
}

async fn insert_space(state: &EngineState) -> Uuid {
    let id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_space (id, name, created_by, updated_by, owner_layer) \
         VALUES ($1, $2, $3, $3, 'project')",
    )
    .bind(id)
    .bind(format!("Scheduling Test Space {id}"))
    .bind(actor)
    .execute(&state.base.db)
    .await
    .expect("insert content_space");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_page(
    state: &EngineState,
    space_id: Uuid,
    status: &str,
    blocks_draft: serde_json::Value,
    blocks_published: Option<serde_json::Value>,
    publish_at: Option<chrono::DateTime<Utc>>,
    unpublish_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_page \
            (id, content_space_id, title, url_path, status, blocks_draft, blocks_published, \
             publish_at, unpublish_at, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)",
    )
    .bind(id)
    .bind(space_id)
    .bind(format!("Scheduling Test Page {id}"))
    .bind(format!("/scheduling-test-{id}"))
    .bind(status)
    .bind(sqlx::types::Json(blocks_draft))
    .bind(blocks_published.map(sqlx::types::Json))
    .bind(publish_at)
    .bind(unpublish_at)
    .bind(actor)
    .execute(&state.base.db)
    .await
    .expect("insert content_page");
    id
}

#[derive(sqlx::FromRow)]
struct PageState {
    status: String,
    blocks_published: Option<serde_json::Value>,
    publish_at: Option<chrono::DateTime<Utc>>,
    unpublish_at: Option<chrono::DateTime<Utc>>,
}

async fn page_state(state: &EngineState, id: Uuid) -> PageState {
    sqlx::query_as(
        "SELECT status, blocks_published, publish_at, unpublish_at \
         FROM content_page WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .expect("read content_page")
}

async fn ingest_row_exists_for(state: &EngineState, page_id: Uuid, event_name: &str) -> bool {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_ingest \
         WHERE payload ->> 'entity_name' = 'content_page' \
           AND payload ->> 'record_id' = $1 \
           AND payload ->> 'event_name' = $2",
    )
    .bind(page_id.to_string())
    .bind(event_name)
    .fetch_one(&state.base.db)
    .await
    .expect("query audit_ingest");
    count > 0
}

fn heading_block(text: &str) -> Block {
    Block {
        id: Uuid::now_v7(),
        kind: BlockKind::Heading,
        props: json!({ "text": text }),
    }
}

#[tokio::test]
async fn a_due_draft_is_published_and_audited_as_the_scheduler() {
    let state = skip_if_no_db!(test_state().await);
    let space_id = insert_space(&state).await;

    let due_at = Utc::now() - chrono::Duration::minutes(5);
    let draft_blocks = json!([heading_block("Hello")]);
    let page_id = insert_page(
        &state,
        space_id,
        "draft",
        draft_blocks.clone(),
        None,
        Some(due_at),
        None,
    )
    .await;

    let stats = attome_content::scheduling::sweep_scheduled_transitions(&state)
        .await
        .expect("sweep_scheduled_transitions");
    assert_eq!(stats.published, 1);
    assert_eq!(stats.unpublished, 0);
    assert_eq!(stats.publish_validation_failed, 0);

    let after = page_state(&state, page_id).await;
    assert_eq!(after.status, "published");
    assert_eq!(after.blocks_published, Some(draft_blocks));
    assert_eq!(
        after.publish_at, None,
        "publish_at must be cleared on consumption, or a later unpublish+republish \
         cycle would silently re-fire this same scheduled publish"
    );
    assert!(
        ingest_row_exists_for(&state, page_id, "content.page.scheduled_publish").await,
        "the scheduler's publish transition must be audited"
    );
}

#[tokio::test]
async fn a_due_published_page_is_reverted_to_draft_and_audited() {
    let state = skip_if_no_db!(test_state().await);
    let space_id = insert_space(&state).await;

    let due_at = Utc::now() - chrono::Duration::minutes(5);
    let published_blocks = json!([heading_block("Live")]);
    let page_id = insert_page(
        &state,
        space_id,
        "published",
        published_blocks.clone(),
        Some(published_blocks.clone()),
        None,
        Some(due_at),
    )
    .await;

    let stats = attome_content::scheduling::sweep_scheduled_transitions(&state)
        .await
        .expect("sweep_scheduled_transitions");
    assert_eq!(stats.unpublished, 1);
    assert_eq!(stats.published, 0);

    let after = page_state(&state, page_id).await;
    assert_eq!(
        after.status, "draft",
        "unpublish must revert status to draft"
    );
    assert_eq!(
        after.blocks_published,
        Some(published_blocks),
        "blocks_published is left in place, not cleared, on an automatic unpublish"
    );
    assert_eq!(
        after.unpublish_at, None,
        "unpublish_at must be cleared on consumption, or a later manual republish \
         would be silently auto-unpublished again on the next tick"
    );
    assert!(
        ingest_row_exists_for(&state, page_id, "content.page.scheduled_unpublish").await,
        "the scheduler's unpublish transition must be audited"
    );
}

#[tokio::test]
async fn a_not_yet_due_schedule_is_left_alone() {
    let state = skip_if_no_db!(test_state().await);
    let space_id = insert_space(&state).await;

    let future = Utc::now() + chrono::Duration::hours(1);
    let draft_id = insert_page(
        &state,
        space_id,
        "draft",
        json!([heading_block("Not yet")]),
        None,
        Some(future),
        None,
    )
    .await;
    let published_id = insert_page(
        &state,
        space_id,
        "published",
        json!([heading_block("Still live")]),
        Some(json!([heading_block("Still live")])),
        None,
        Some(future),
    )
    .await;

    let stats = attome_content::scheduling::sweep_scheduled_transitions(&state)
        .await
        .expect("sweep_scheduled_transitions");
    assert_eq!(stats.published, 0);
    assert_eq!(stats.unpublished, 0);

    assert_eq!(page_state(&state, draft_id).await.status, "draft");
    assert_eq!(page_state(&state, published_id).await.status, "published");
}

#[tokio::test]
async fn a_due_draft_that_fails_block_validation_is_skipped_not_force_published() {
    let state = skip_if_no_db!(test_state().await);
    let space_id = insert_space(&state).await;

    let due_at = Utc::now() - chrono::Duration::minutes(5);
    // An empty "text" prop fails `blocks::validate_blocks` for a Heading
    // block (see `blocks.rs::require_nonempty_str`) — same shape a draft
    // saved invalid, or one whose registry rules tightened after it was
    // saved, would produce.
    let invalid_blocks =
        json!([{ "id": Uuid::now_v7(), "kind": "heading", "props": { "text": "" } }]);
    let page_id = insert_page(
        &state,
        space_id,
        "draft",
        invalid_blocks,
        None,
        Some(due_at),
        None,
    )
    .await;

    let stats = attome_content::scheduling::sweep_scheduled_transitions(&state)
        .await
        .expect("sweep_scheduled_transitions");
    assert_eq!(stats.published, 0);
    assert_eq!(stats.publish_validation_failed, 1);

    let after = page_state(&state, page_id).await;
    assert_eq!(
        after.status, "draft",
        "an invalid due draft must stay in draft, never be force-published"
    );
    assert_eq!(
        after.publish_at,
        Some(due_at),
        "publish_at must stay set so a later-fixed draft still goes out on the next tick"
    );
}

#[tokio::test]
async fn running_the_sweep_twice_does_not_double_publish() {
    let state = skip_if_no_db!(test_state().await);
    let space_id = insert_space(&state).await;

    let due_at = Utc::now() - chrono::Duration::minutes(5);
    let page_id = insert_page(
        &state,
        space_id,
        "draft",
        json!([heading_block("Idempotent")]),
        None,
        Some(due_at),
        None,
    )
    .await;

    let first = attome_content::scheduling::sweep_scheduled_transitions(&state)
        .await
        .expect("first sweep");
    assert_eq!(first.published, 1);

    let second = attome_content::scheduling::sweep_scheduled_transitions(&state)
        .await
        .expect("second sweep");
    assert_eq!(
        second.published, 0,
        "a page already published by the first tick must not be re-published by the second"
    );

    assert_eq!(page_state(&state, page_id).await.status, "published");
}
