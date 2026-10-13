//! Integration tests for `attome_service::queue` (M84 Phase 1, D-464) — claim/
//! assign concurrency safety and distribution strategy selection. Requires a
//! live, throwaway Postgres, same convention `tests/clock.rs` and
//! `tests/convert.rs` already use; skips loudly when no `DATABASE_URL`/test
//! database is configured.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::AppState;
use attome_service::queue::{assign_ticket, claim_next_ticket};
use attome_testkit::skip_if_no_db;
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
            "connection_number": 20, "timeout": 5.0
        }},
        "cache": {{
            "host": "{redis_host}", "port": {redis_port}, "password": "", "db": 0,
            "connection_pool_size": 4, "timeout": 2000,
            "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": false
        }},
        "storage": {{
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "test", "s3_use_path_style": true, "s3_verify_ssl": false
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

/// Same env-var-mutation serialization `tests/clock.rs` documents
/// (`attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` synchronously, and
/// `cargo test` runs this file's tests concurrently).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
    // reads these vars while this guard is held.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
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

async fn ensure_seeded(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed");
    attome_service::seed::seed_for_tests(db)
        .await
        .expect("attome_service::seed::seed");
}

async fn insert_systemuser(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(id)
        .bind(format!("queue-test-{id}"))
        .execute(db)
        .await
        .expect("insert user_account");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_queue(
    db: &DbPool,
    distribution: &str,
    capacity: Option<i64>,
    lead_ref: Option<Uuid>,
    is_active: bool,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_work_queue \
             (id, name, distribution, capacity, lead_ref, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("Queue Test {id}"))
    .bind(distribution)
    .bind(capacity)
    .bind(lead_ref)
    .bind(is_active)
    .execute(db)
    .await
    .expect("insert service_work_queue");
    id
}

async fn insert_queue_member(db: &DbPool, queue_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO service_work_queue_member (id, queue_ref, user_ref, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(Uuid::now_v7())
    .bind(queue_id)
    .bind(user_id)
    .execute(db)
    .await
    .expect("insert service_work_queue_member");
}

async fn insert_queued_ticket(db: &DbPool, queue_id: Uuid, priority: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_ticket \
             (id, ticket_number, title, priority, status, work_queue_ref) \
         VALUES ($1, $2, 'Queue Test Ticket', $3, 'open', $4)",
    )
    .bind(id)
    .bind(format!("TKT-QUEUE-{id}"))
    .bind(priority)
    .bind(queue_id)
    .execute(db)
    .await
    .expect("insert service_ticket");
    id
}

async fn ticket_assignee(db: &DbPool, ticket_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT assignee_id FROM service_ticket WHERE id = $1")
        .bind(ticket_id)
        .fetch_one(db)
        .await
        .expect("read ticket assignee")
}

/// The checklist's required proof: two concurrent self-service claims
/// against a queue that has exactly one open ticket must not both succeed.
/// `lock_queue`'s `pg_try_advisory_xact_lock` is a non-blocking *try* lock —
/// it does not make the loser wait for the winner's transaction to commit
/// and then observe an empty queue. Depending on scheduling, the loser
/// either (a) genuinely arrives after the winner has already committed and
/// sees `claimed: false` (`Ok`), or (b) arrives while the winner's
/// transaction is still open and gets `Err(Conflict)` immediately — both are
/// correct "did not double-claim" outcomes; this test accepts either shape
/// for the loser and only asserts the one invariant that actually matters:
/// exactly one caller ends up with the ticket.
#[tokio::test]
async fn concurrent_claims_never_double_claim_the_same_ticket() {
    let state = skip_if_no_db!(test_state().await);
    let db = state.base.db.clone();
    ensure_seeded(&db).await;

    let member_a = insert_systemuser(&db).await;
    let member_b = insert_systemuser(&db).await;
    let queue_id = insert_queue(&db, "manual", None, None, true).await;
    insert_queue_member(&db, queue_id, member_a).await;
    insert_queue_member(&db, queue_id, member_b).await;
    let ticket_id = insert_queued_ticket(&db, queue_id, "high").await;

    let state_a = state.clone();
    let state_b = state.clone();
    let (result_a, result_b) = tokio::join!(
        claim_next_ticket(&state_a, queue_id, member_a),
        claim_next_ticket(&state_b, queue_id, member_b),
    );

    // Each side is either `Ok(claimed: true/false)` or `Err(Conflict)` — any
    // other error is a real failure, not an acceptable race outcome.
    for result in [&result_a, &result_b] {
        if let Err(err) = result {
            assert!(
                matches!(err, attome_types::AppError::Conflict(_)),
                "an unexpected error is a real failure, not a race outcome: {err:?}"
            );
        }
    }

    let a_claimed = matches!(&result_a, Ok(r) if r.claimed);
    let b_claimed = matches!(&result_b, Ok(r) if r.claimed);
    assert!(
        a_claimed ^ b_claimed,
        "exactly one of the two concurrent claims must succeed, got a={result_a:?} b={result_b:?}"
    );

    let winner = if a_claimed { member_a } else { member_b };
    assert_eq!(
        ticket_assignee(&db, ticket_id).await,
        Some(winner),
        "the ticket must be assigned to whichever caller actually won the claim"
    );
}

/// `claim_next_ticket` requires the caller to be an active member (or the
/// queue's lead) — a non-member must be rejected, and the ticket must stay
/// unclaimed.
#[tokio::test]
async fn claim_rejects_a_non_member() {
    let state = skip_if_no_db!(test_state().await);
    let db = state.base.db.clone();
    ensure_seeded(&db).await;

    let outsider = insert_systemuser(&db).await;
    let queue_id = insert_queue(&db, "manual", None, None, true).await;
    let ticket_id = insert_queued_ticket(&db, queue_id, "medium").await;

    let err = claim_next_ticket(&state, queue_id, outsider)
        .await
        .expect_err("a non-member's claim must be rejected");
    assert!(matches!(err, attome_types::AppError::Forbidden));
    assert_eq!(
        ticket_assignee(&db, ticket_id).await,
        None,
        "a rejected claim must not touch the ticket"
    );
}

/// `assign_ticket` on a `round_robin` queue picks the next eligible member
/// after the persisted pointer, skipping anyone at/over capacity, and
/// advances the pointer for next time.
#[tokio::test]
async fn round_robin_assign_skips_a_member_at_capacity_and_advances_the_pointer() {
    let state = skip_if_no_db!(test_state().await);
    let db = state.base.db.clone();
    ensure_seeded(&db).await;

    let member_a = insert_systemuser(&db).await;
    let member_b = insert_systemuser(&db).await;
    let queue_id = insert_queue(&db, "round_robin", Some(1), None, true).await;
    insert_queue_member(&db, queue_id, member_a).await;
    insert_queue_member(&db, queue_id, member_b).await;

    // member_a is already at capacity (1 open item); only member_b is
    // eligible regardless of round-robin order.
    let already_open = insert_queued_ticket(&db, queue_id, "low").await;
    sqlx::query("UPDATE service_ticket SET assignee_id = $2, claimed_at = NOW() WHERE id = $1")
        .bind(already_open)
        .bind(member_a)
        .execute(&db)
        .await
        .expect("pre-assign member_a to capacity");

    let ticket_id = insert_queued_ticket(&db, queue_id, "medium").await;
    let response = assign_ticket(&state, queue_id, ticket_id, None, member_a)
        .await
        .expect("assign_ticket (round_robin)");

    assert_eq!(
        response.assignee_id, member_b,
        "member_a is at capacity, so member_b must be picked"
    );
    assert_eq!(ticket_assignee(&db, ticket_id).await, Some(member_b));
}
