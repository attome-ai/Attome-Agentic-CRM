//! P-environment-promotion §5 step 11/12 — the plan/apply ledger
//! (`metadata_bundle_plan`, migration 0134;
//! `attome_api::bundle::ledger`) against a live database:
//!
//! - `insert_plan` → `get_plan` round-trips every column; an unknown id is
//!   `None`;
//! - `list_plans` is newest-first and honours `limit`;
//! - `mark_queued` is a CAS on `planned` — `true` once, `false` after;
//! - `claim` is a row-CAS: a `queued` row is won exactly once (a second
//!   claim returns `None`), a `planned` row is never claimable, a stale
//!   `claimed`/`applying` row (no progress for `CLAIM_TIMEOUT`) is reclaimed
//!   and a fresh one is not;
//! - `advance` sets `applying` + cursor/applied_count, `mark_succeeded` /
//!   `mark_failed` close the row (and refuse a row that is not running);
//! - `latest_succeeded` is the newest `succeeded` row, `None` with none;
//! - `enqueue_apply` (one transaction: `planned|queued -> queued` + a
//!   dedup-keyed `ApplyMetadataBundle` queue row) is idempotent and refuses
//!   a plan that is past queueing.
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`); the `enqueue_apply` test additionally needs Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) only because building an
//! `EngineState` connects to it — no test here reads or writes Redis. The
//! template `DATABASE_URL` names must be migrated through
//! `0134_metadata_bundle_plan` or later.
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic%20-c%20statement_timeout%3D60000"
//! $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test bundle_ledger -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::bundle::ledger::{
    self, CLAIM_TIMEOUT, PlanStatus, advance, claim, get_plan, insert_plan, latest_succeeded,
    list_plans, mark_failed, mark_queued, mark_succeeded,
};
use attome_db::DbPool;
use attome_testkit::migrated_pool_or_skip;
use uuid::Uuid;

/// A distinct bundle/plan payload per row so round-trip assertions can tell
/// rows apart.
fn payloads(tag: &str) -> (serde_json::Value, serde_json::Value) {
    (
        serde_json::json!({ "format": "attome-bundle/v1", "tag": tag, "entities": [] }),
        serde_json::json!({ "entries": [{ "component": "entity", "key": tag, "action": "create" }] }),
    )
}

async fn insert(db: &DbPool, tag: &str, allow_retire: bool, requested_by: Option<Uuid>) -> Uuid {
    let (bundle, plan) = payloads(tag);
    insert_plan(
        db,
        &bundle,
        &plan,
        &format!("bundle-hash-{tag}"),
        &format!("basis-hash-{tag}"),
        "attome-bundle/v1",
        "0.0.0-test",
        allow_retire,
        requested_by,
    )
    .await
    .expect("insert_plan")
}

/// Pushes a row's claim/progress timestamps back past `CLAIM_TIMEOUT` —
/// the only way to simulate a crashed worker without sleeping 30 minutes.
/// A test-only write against the test binary's own throwaway database.
async fn age_claim(db: &DbPool, id: Uuid) {
    sqlx::query(&format!(
        "UPDATE metadata_bundle_plan \
         SET claimed_at = NOW() - INTERVAL '{CLAIM_TIMEOUT}' - INTERVAL '1 minute', \
             updated_at = NOW() - INTERVAL '{CLAIM_TIMEOUT}' - INTERVAL '1 minute' \
         WHERE id = $1"
    ))
    .bind(id)
    .execute(db)
    .await
    .expect("age claim");
}

#[tokio::test]
async fn insert_then_get_round_trips_every_column() {
    let db = migrated_pool_or_skip!();
    let requester = Uuid::now_v7();
    let tag = attome_testkit::unique("ledger-rt");
    let (bundle, plan) = payloads(&tag);
    let id = insert(&db, &tag, true, Some(requester)).await;

    let row = get_plan(&db, id)
        .await
        .expect("get_plan")
        .expect("row exists");
    assert_eq!(row.id, id);
    assert_eq!(row.status, PlanStatus::Planned);
    assert_eq!(row.bundle, bundle);
    assert_eq!(row.plan, plan);
    assert_eq!(row.bundle_hash, format!("bundle-hash-{tag}"));
    assert_eq!(row.basis_hash, format!("basis-hash-{tag}"));
    assert_eq!(row.format_version, "attome-bundle/v1");
    assert_eq!(row.platform_version, "0.0.0-test");
    assert!(row.allow_retire);
    assert_eq!(row.requested_by, Some(requester));
    assert_eq!(row.approval_ref, None);
    assert_eq!(row.cursor, 0);
    assert_eq!(row.applied_count, 0);
    assert_eq!(row.error_message, None);
    assert!(row.claimed_at.is_none());
    assert!(row.finished_at.is_none());

    assert!(
        get_plan(&db, Uuid::now_v7())
            .await
            .expect("get_plan")
            .is_none()
    );
}

#[tokio::test]
async fn list_is_newest_first_and_bounded() {
    let db = migrated_pool_or_skip!();
    let tag = attome_testkit::unique("ledger-list");
    let first = insert(&db, &format!("{tag}-1"), false, None).await;
    let second = insert(&db, &format!("{tag}-2"), false, None).await;
    let third = insert(&db, &format!("{tag}-3"), false, None).await;

    let rows = list_plans(&db, 200, None).await.expect("list_plans");
    let ours: Vec<Uuid> = rows
        .iter()
        .map(|r| r.id)
        .filter(|id| [first, second, third].contains(id))
        .collect();
    assert_eq!(ours, vec![third, second, first], "newest first");

    // created_at DESC, id DESC — uuidv7 ids are time-ordered, so the newest
    // of ours is the first row overall unless another binary inserted later
    // (it cannot: D-343 gives this binary its own database).
    let limited = list_plans(&db, 1, None).await.expect("list_plans limit 1");
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].id, third);
}

#[tokio::test]
async fn mark_queued_is_a_cas_on_planned() {
    let db = migrated_pool_or_skip!();
    let id = insert(&db, &attome_testkit::unique("ledger-queue"), false, None).await;
    let approval = Uuid::now_v7();

    assert!(
        mark_queued(&db, id, Some(approval))
            .await
            .expect("mark_queued")
    );
    let row = get_plan(&db, id).await.expect("get").expect("row");
    assert_eq!(row.status, PlanStatus::Queued);
    assert_eq!(row.approval_ref, Some(approval));

    // Already queued — no-op, and the approval reference is NOT overwritten.
    assert!(
        !mark_queued(&db, id, Some(Uuid::now_v7()))
            .await
            .expect("mark_queued again")
    );
    let row = get_plan(&db, id).await.expect("get").expect("row");
    assert_eq!(row.approval_ref, Some(approval));

    // Unknown id — false, not an error.
    assert!(
        !mark_queued(&db, Uuid::now_v7(), None)
            .await
            .expect("mark_queued unknown")
    );
}

#[tokio::test]
async fn claim_is_won_once_and_never_on_a_planned_row() {
    let db = migrated_pool_or_skip!();
    let id = insert(&db, &attome_testkit::unique("ledger-claim"), false, None).await;

    // Still `planned`: not claimable — the apply path must queue it first.
    assert!(claim(&db, id, "worker-a").await.expect("claim").is_none());

    assert!(mark_queued(&db, id, None).await.expect("queue"));
    let won = claim(&db, id, "worker-a")
        .await
        .expect("claim")
        .expect("worker-a wins");
    assert_eq!(won.status, PlanStatus::Claimed);
    assert!(won.claimed_at.is_some());
    assert_eq!(won.cursor, 0);

    // A second worker racing the same row loses: the claim is live.
    assert!(claim(&db, id, "worker-b").await.expect("claim").is_none());
    let claimed_by: Option<String> =
        sqlx::query_scalar("SELECT claimed_by FROM metadata_bundle_plan WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("claimed_by");
    assert_eq!(claimed_by.as_deref(), Some("worker-a"));
}

#[tokio::test]
async fn stale_claim_is_reclaimed_and_resumes_from_cursor() {
    let db = migrated_pool_or_skip!();
    let id = insert(&db, &attome_testkit::unique("ledger-stale"), false, None).await;
    assert!(mark_queued(&db, id, None).await.expect("queue"));
    assert!(claim(&db, id, "worker-a").await.expect("claim").is_some());
    advance(&db, id, 3, 2).await.expect("advance");

    // Fresh progress: NOT reclaimable even though the status is `applying`.
    assert!(claim(&db, id, "worker-b").await.expect("claim").is_none());

    // Crashed worker: both claimed_at and updated_at are older than the
    // timeout → the next pass takes over, and sees the cursor it left.
    age_claim(&db, id).await;
    let reclaimed = claim(&db, id, "worker-b")
        .await
        .expect("claim")
        .expect("reclaimed");
    assert_eq!(reclaimed.status, PlanStatus::Claimed);
    assert_eq!(reclaimed.cursor, 3);
    assert_eq!(reclaimed.applied_count, 2);
    let claimed_by: Option<String> =
        sqlx::query_scalar("SELECT claimed_by FROM metadata_bundle_plan WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("claimed_by");
    assert_eq!(claimed_by.as_deref(), Some("worker-b"));
}

#[tokio::test]
async fn advance_then_succeed_closes_the_row() {
    let db = migrated_pool_or_skip!();
    let id = insert(&db, &attome_testkit::unique("ledger-ok"), false, None).await;

    // Not running yet: advance/succeed are refused.
    assert!(matches!(
        advance(&db, id, 1, 1).await,
        Err(attome_types::AppError::Conflict(_))
    ));
    assert!(matches!(
        mark_succeeded(&db, id).await,
        Err(attome_types::AppError::Conflict(_))
    ));

    assert!(mark_queued(&db, id, None).await.expect("queue"));
    assert!(claim(&db, id, "worker-a").await.expect("claim").is_some());
    advance(&db, id, 1, 1).await.expect("advance 1");
    advance(&db, id, 2, 2).await.expect("advance 2");
    let row = get_plan(&db, id).await.expect("get").expect("row");
    assert_eq!(row.status, PlanStatus::Applying);
    assert_eq!(row.cursor, 2);
    assert_eq!(row.applied_count, 2);

    mark_succeeded(&db, id).await.expect("succeed");
    let row = get_plan(&db, id).await.expect("get").expect("row");
    assert_eq!(row.status, PlanStatus::Succeeded);
    assert!(row.finished_at.is_some());
    assert_eq!(row.error_message, None);

    // Terminal: nothing moves it again.
    assert!(claim(&db, id, "worker-b").await.expect("claim").is_none());
    assert!(matches!(
        advance(&db, id, 3, 3).await,
        Err(attome_types::AppError::Conflict(_))
    ));
    assert!(matches!(
        mark_failed(&db, id, "too late").await,
        Err(attome_types::AppError::Conflict(_))
    ));
}

#[tokio::test]
async fn mark_failed_records_a_bounded_error() {
    let db = migrated_pool_or_skip!();
    let id = insert(&db, &attome_testkit::unique("ledger-fail"), false, None).await;

    // `planned` cannot fail (it never ran); `queued` can (refused before claim).
    assert!(matches!(
        mark_failed(&db, id, "nope").await,
        Err(attome_types::AppError::Conflict(_))
    ));
    assert!(mark_queued(&db, id, None).await.expect("queue"));
    let long_error = "x".repeat(10_000);
    mark_failed(&db, id, &long_error).await.expect("fail");
    let row = get_plan(&db, id).await.expect("get").expect("row");
    assert_eq!(row.status, PlanStatus::Failed);
    assert!(row.finished_at.is_some());
    assert_eq!(
        row.error_message.as_ref().map(String::len),
        Some(4_000),
        "error text is bounded"
    );

    // And a running row can fail too, then stays terminal.
    let id2 = insert(&db, &attome_testkit::unique("ledger-fail2"), false, None).await;
    assert!(mark_queued(&db, id2, None).await.expect("queue"));
    assert!(claim(&db, id2, "worker-a").await.expect("claim").is_some());
    advance(&db, id2, 1, 0).await.expect("advance");
    mark_failed(&db, id2, "reconcile refused field type change")
        .await
        .expect("fail");
    assert!(matches!(
        mark_succeeded(&db, id2).await,
        Err(attome_types::AppError::Conflict(_))
    ));
    let row = get_plan(&db, id2).await.expect("get").expect("row");
    assert_eq!(row.status, PlanStatus::Failed);
    assert_eq!(
        row.error_message.as_deref(),
        Some("reconcile refused field type change")
    );
}

#[tokio::test]
async fn latest_succeeded_is_the_newest_succeeded_row() {
    let db = migrated_pool_or_skip!();
    // Other tests in this binary may have succeeded rows already; assert
    // relative to the ones this test creates.
    let tag = attome_testkit::unique("ledger-latest");
    let older = insert(&db, &format!("{tag}-older"), false, None).await;
    let newer = insert(&db, &format!("{tag}-newer"), false, None).await;
    let never = insert(&db, &format!("{tag}-never"), false, None).await;
    for id in [older, newer] {
        assert!(mark_queued(&db, id, None).await.expect("queue"));
        assert!(claim(&db, id, "worker").await.expect("claim").is_some());
        mark_succeeded(&db, id).await.expect("succeed");
    }
    // `never` is queued and failed — must not be picked.
    assert!(mark_queued(&db, never, None).await.expect("queue"));
    mark_failed(&db, never, "blocked").await.expect("fail");

    let latest = latest_succeeded(&db)
        .await
        .expect("latest_succeeded")
        .expect("at least one succeeded row");
    assert_eq!(latest.status, PlanStatus::Succeeded);
    assert_eq!(latest.id, newer, "newest finished_at wins");
}

#[tokio::test]
async fn succeeded_bundles_by_name_filters_and_orders_newest_first() {
    let db = migrated_pool_or_skip!();
    let name = attome_testkit::unique("ledger-named");
    let other_name = attome_testkit::unique("ledger-named-other");

    async fn insert_named(db: &DbPool, name: &str, version: &str) -> Uuid {
        let bundle = serde_json::json!({
            "format": "attome-bundle/v1", "name": name, "version": version, "entities": []
        });
        let plan = serde_json::json!({ "entries": [] });
        insert_plan(
            db,
            &bundle,
            &plan,
            &format!("hash-{name}-{version}"),
            &format!("basis-{name}-{version}"),
            "attome-bundle/v1",
            "0.0.0-test",
            false,
            None,
        )
        .await
        .expect("insert_plan")
    }

    // M92 Phase 1 — `succeeded_bundles_by_name` backs both the rollback
    // route's snapshot lookup and `plan::check_bundle_dependencies`'s
    // highest-applied-version check: it must filter to this `name`, only
    // `succeeded` rows, newest first.
    let v1 = insert_named(&db, &name, "1.0.0").await;
    let v2 = insert_named(&db, &name, "2.0.0").await;
    let unrelated = insert_named(&db, &other_name, "9.9.9").await;
    let never_succeeded = insert_named(&db, &name, "3.0.0").await;

    for id in [v1, v2, unrelated] {
        assert!(mark_queued(&db, id, None).await.expect("queue"));
        assert!(claim(&db, id, "worker").await.expect("claim").is_some());
        mark_succeeded(&db, id).await.expect("succeed");
    }
    // `never_succeeded` stays `planned` — must not appear.

    let rows = ledger::succeeded_bundles_by_name(&db, &name)
        .await
        .expect("succeeded_bundles_by_name");
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![v2, v1],
        "newest succeeded first, filtered to this name"
    );
    assert!(!ids.contains(&unrelated), "a different name is excluded");
    assert!(
        !ids.contains(&never_succeeded),
        "a row that never succeeded is excluded"
    );
    assert!(
        ledger::succeeded_bundles_by_name(&db, &attome_testkit::unique("ledger-named-none"))
            .await
            .expect("succeeded_bundles_by_name unknown name")
            .is_empty()
    );
}

// ── enqueue_apply needs an EngineState (only for `state.base.db`) ──────────────

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config() -> attome_config::AppConfig {
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
            "approval": {{ "required_actions": [] }}
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

/// A bare `EngineState` over this binary's throwaway database — no
/// `EngineSystem::build`, no seeds: `enqueue_apply` touches only
/// `state.base.db`.
async fn test_state() -> Option<attome_core::EngineState> {
    attome_testkit::migrated_db_url()?;
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
    let base = attome_server::AppState::new(
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    Some(attome_core::EngineState::new(base))
}

async fn apply_job_rows_for(db: &DbPool, plan_id: Uuid) -> i64 {
    // `payload` is the versioned envelope: {"variant": ..., "payload": {"plan_id": ...}}.
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs \
         WHERE job->>'variant' = 'ApplyMetadataBundle' \
           AND job->'payload'->>'plan_id' = $1",
    )
    .bind(plan_id.to_string())
    .fetch_one(db)
    .await
    .expect("count apply jobs")
}

#[tokio::test]
async fn enqueue_apply_queues_once_and_refuses_a_running_plan() {
    let Some(state) = test_state().await else {
        eprintln!("SKIP bundle_ledger::enqueue_apply: no DATABASE_URL");
        return;
    };
    let db = &state.base.db;

    // planned -> queued + one job.
    let id = insert(db, &attome_testkit::unique("ledger-enqueue"), false, None).await;
    ledger::enqueue_apply(&state, id)
        .await
        .expect("enqueue_apply");
    let row = get_plan(db, id).await.expect("get").expect("row");
    assert_eq!(row.status, PlanStatus::Queued);
    assert_eq!(apply_job_rows_for(db, id).await, 1);

    // Already queued (e.g. `mark_queued` ran first, or a retry): tolerated,
    // and the dedup key collapses the second enqueue.
    ledger::enqueue_apply(&state, id)
        .await
        .expect("enqueue_apply again");
    assert_eq!(
        apply_job_rows_for(db, id).await,
        1,
        "dedup-keyed on plan id"
    );

    // Past queueing: refused, nothing enqueued.
    assert!(claim(db, id, "worker").await.expect("claim").is_some());
    assert!(matches!(
        ledger::enqueue_apply(&state, id).await,
        Err(attome_types::AppError::Conflict(_))
    ));
    assert_eq!(apply_job_rows_for(db, id).await, 1);

    // Unknown plan: NotFound.
    assert!(matches!(
        ledger::enqueue_apply(&state, Uuid::now_v7()).await,
        Err(attome_types::AppError::NotFound)
    ));
}
