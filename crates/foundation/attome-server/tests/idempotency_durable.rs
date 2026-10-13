//! P-idempotency-hardening §4.4 (Phase 3) — live-verified against a real
//! Postgres, per `idempotency_durable.rs`'s own module-doc TODO: "acquire/
//! replay/conflict round trip, concurrent acquire race..., and the
//! `complete_in_tx` atomicity claim itself."
//!
//! Env: DATABASE_URL (a throwaway database, NEVER attome_dev), TEST_REDIS_HOST/
//! TEST_REDIS_PORT, migration 0066 (`idempotency_record`) already applied.
//! Skips (loudly) when DATABASE_URL is unset, except under `CI`, where an
//! unset value is a wiring failure and panics; see `attome_testkit`.
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-server --test idempotency_durable -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_server::AppState;
use attome_server::middleware::idempotency_durable::{
    AcquireOutcome, acquire_or_check, complete_in_tx, release_on_failure,
};
use sqlx::PgPool;
use uuid::Uuid;

use attome_testkit::skip_if_no_db;

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
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 5, "timeout": 5.0
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
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "attome-test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
/// Skips locally, panics under `CI`; see `attome_testkit` (F-008, TODO-008a).
async fn test_state() -> Option<AppState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let config = test_config();

    let db = PgPool::connect(&db_url)
        .await
        .expect("connect DATABASE_URL");
    let db_readonly = db.clone();
    let db_migrator = db.clone();
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

    Some(AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    ))
}

/// `idempotency_record.principal_ref` has a real FK to
/// `user_account` — seed a throwaway user row so `acquire_or_check`'s
/// INSERT doesn't trip the constraint.
async fn seed_throwaway_user(db: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, is_active, created_at) VALUES ($1, $2, true, now())",
    )
    .bind(id)
    .bind(attome_testkit::unique_email("idempotency-test"))
    .execute(db)
    .await
    .expect("seed throwaway user_account row");
    id
}

async fn random_identity(db: &PgPool) -> (Uuid, &'static str, String, String) {
    (
        seed_throwaway_user(db).await,
        "POST",
        format!("op-{}", Uuid::now_v7()),
        format!("client-key-{}", Uuid::now_v7()),
    )
}

/// The load-bearing round trip: acquire a fresh key, complete it, then a
/// retry with the identical identity + body_hash replays the completed
/// response verbatim rather than re-running the operation.
#[tokio::test]
async fn acquire_complete_then_retry_replays_the_completed_response() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;
    let body_hash = "hash-a";

    let first = acquire_or_check(
        &state,
        principal,
        method,
        &operation,
        &client_key,
        body_hash,
    )
    .await
    .expect("first acquire_or_check call");
    let AcquireOutcome::Acquired { record_id } = first else {
        panic!("expected Acquired for a brand-new identity");
    };

    let mut tx = state.db.begin().await.expect("begin tx");
    complete_in_tx(
        &mut tx,
        record_id,
        None,
        201,
        &[("content-type".to_string(), "application/json".to_string())],
        b"{\"ok\":true}",
    )
    .await
    .expect("complete_in_tx");
    tx.commit().await.expect("commit");

    let second = acquire_or_check(
        &state,
        principal,
        method,
        &operation,
        &client_key,
        body_hash,
    )
    .await
    .expect("second acquire_or_check call");
    match second {
        AcquireOutcome::Replay(cached) => {
            assert_eq!(cached.status, 201);
            assert_eq!(cached.body, b"{\"ok\":true}");
            assert!(
                cached
                    .headers
                    .iter()
                    .any(|(k, v)| k == "content-type" && v == "application/json")
            );
        }
        _ => panic!("expected Replay after completion, got a different outcome"),
    }
}

/// Reusing the same identity with a DIFFERENT body_hash must be rejected as
/// `DifferentRequest`, never silently treated as a fresh key or a replay.
#[tokio::test]
async fn same_identity_different_body_hash_is_rejected() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire_or_check call");
    assert!(matches!(first, AcquireOutcome::Acquired { .. }));

    let second = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-b")
        .await
        .expect("second acquire_or_check call");
    assert!(
        matches!(second, AcquireOutcome::DifferentRequest),
        "a different body_hash under the same identity must be rejected as DifferentRequest"
    );
}

/// A second acquire attempt for a still-`pending` (never completed) record
/// must report `InProgress`, never silently re-run the operation.
#[tokio::test]
async fn a_still_pending_record_reports_in_progress_not_a_second_acquire() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire_or_check call");
    assert!(matches!(first, AcquireOutcome::Acquired { .. }));

    let second = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("second acquire_or_check call");
    assert!(
        matches!(second, AcquireOutcome::InProgress),
        "a still-pending record must report InProgress, not Acquired again"
    );
}

/// The atomicity claim `complete_in_tx`'s own doc comment makes: a
/// transaction that calls `complete_in_tx` and then rolls back (instead of
/// committing) must leave the record `pending`, not `completed` — proving
/// the completion write really is part of the same commit as the caller's
/// own mutation, not a separate write that could survive the mutation's own
/// rollback.
#[tokio::test]
async fn complete_in_tx_is_rolled_back_with_its_enclosing_transaction() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire_or_check call");
    let AcquireOutcome::Acquired { record_id } = first else {
        panic!("expected Acquired for a brand-new identity");
    };

    let mut tx = state.db.begin().await.expect("begin tx");
    complete_in_tx(&mut tx, record_id, None, 200, &[], b"body")
        .await
        .expect("complete_in_tx");
    tx.rollback().await.expect("rollback");

    let state_after: String =
        sqlx::query_scalar("SELECT state FROM idempotency_record WHERE id = $1")
            .bind(record_id)
            .fetch_one(&state.db)
            .await
            .expect("record must still exist");
    assert_eq!(
        state_after, "pending",
        "a rolled-back complete_in_tx must leave the record pending, not completed"
    );

    // And a retry against the still-pending record correctly reports
    // InProgress, not a replay of a completion that never actually landed.
    let retry = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("retry acquire_or_check call");
    assert!(matches!(retry, AcquireOutcome::InProgress));
}

/// P0.3 / B1 (BSV-F05) — a completion that has lost ownership must fail, and
/// failing must roll the caller's transaction back. Acquire as A, backdate the
/// row past `STALE_PENDING_AFTER`, let B reclaim and complete it, then prove A's
/// late `complete_in_tx` is refused (today it returns `Ok` and overwrites B's
/// completion, letting a replay serve the wrong attempt's response).
#[tokio::test]
async fn a_completion_that_lost_ownership_rolls_back_its_transaction() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    // A acquires.
    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("A's acquire_or_check call");
    let AcquireOutcome::Acquired { record_id } = first else {
        panic!("expected Acquired for a brand-new identity");
    };

    // The original request is abandoned long enough for a retry to reclaim it.
    sqlx::query(
        "UPDATE idempotency_record SET updated_at = NOW() - INTERVAL '6 minutes' \
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&state.db)
    .await
    .expect("backdate updated_at to simulate lost ownership");

    // B reclaims the same record and completes it.
    let reclaimed = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("B's acquire_or_check call");
    let AcquireOutcome::Acquired {
        record_id: reclaimed_id,
    } = reclaimed
    else {
        panic!("expected the stale record to be reclaimed as Acquired");
    };
    assert_eq!(reclaimed_id, record_id, "a reclaim reuses the record id");
    complete(&state, reclaimed_id, b"{\"by\":\"B\"}").await;

    // A now completes late. It no longer owns the record, so this must fail —
    // not silently overwrite B's completion.
    let mut tx = state.db.begin().await.expect("begin A's transaction");
    let result = complete_in_tx(&mut tx, record_id, None, 201, &[], b"{\"by\":\"A\"}");
    assert!(
        result.await.is_err(),
        "a completion whose record was reclaimed by another holder must be refused (BSV-F05)"
    );
    tx.rollback().await.expect("rollback A's transaction");

    // B's completion is intact and replays.
    let retry = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("replay acquire_or_check call");
    match retry {
        AcquireOutcome::Replay(cached) => {
            assert_eq!(
                cached.body, b"{\"by\":\"B\"}",
                "B's completion must survive A's late attempt"
            );
        }
        other => panic!(
            "expected B's completed response to replay, got {}",
            outcome_name(&other)
        ),
    }
}

/// P0.2 / B2 (BSV-F04) — after the retention sweep soft-deletes a completed
/// record, the SAME key must acquire afresh: the client's 24 h window elapsed,
/// the row is history rather than a live claim. Before B2 the unique
/// constraint (which ignores `is_deleted`) made the fresh INSERT conflict and
/// the caller was told `InProgress` forever.
#[tokio::test]
async fn a_key_reused_after_the_retention_sweep_acquires_afresh() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire");
    let AcquireOutcome::Acquired { record_id } = first else {
        panic!("expected Acquired for a brand-new identity");
    };
    complete(&state, record_id, b"{\"ok\":true}").await;

    // Exactly what PlatformJob::PruneIdempotencyRecords does to a record past
    // `durable_retention_hours`.
    sqlx::query("UPDATE idempotency_record SET is_deleted = TRUE WHERE id = $1")
        .bind(record_id)
        .execute(&state.db)
        .await
        .expect("soft-delete the completed row as the retention sweep does");

    let reused = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("reused-key acquire_or_check call");
    assert!(
        matches!(reused, AcquireOutcome::Acquired { .. }),
        "a key reused after the retention sweep must acquire afresh, got {}",
        outcome_name(&reused)
    );
}

/// B2 (BSV-F04): a `pending` row the sweep soft-deleted is never handed back
/// by the stale reclaim (its completion could never be replayed); the retry
/// gets a fresh record instead.
#[tokio::test]
async fn a_pruned_pending_row_is_not_reclaimed() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire");
    let AcquireOutcome::Acquired { record_id } = first else {
        panic!("expected Acquired for a brand-new identity");
    };
    sqlx::query(
        "UPDATE idempotency_record
         SET is_deleted = TRUE, updated_at = NOW() - INTERVAL '2 days'
         WHERE id = $1",
    )
    .bind(record_id)
    .execute(&state.db)
    .await
    .expect("sweep the stale pending row");

    let retry = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("retry acquire");
    let AcquireOutcome::Acquired {
        record_id: fresh_id,
    } = retry
    else {
        panic!(
            "a swept pending key must acquire, got {}",
            outcome_name(&retry)
        );
    };
    assert_ne!(fresh_id, record_id, "the swept row must not be reclaimed");

    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM idempotency_record
         WHERE principal_ref = $1 AND operation = $2 AND client_key = $3",
    )
    .bind(principal)
    .bind(&operation)
    .bind(&client_key)
    .fetch_one(&state.db)
    .await
    .expect("count rows");
    assert_eq!(live, 1, "exactly the fresh row remains for the identity");
}

/// `release_on_failure` must free a pending record for a legitimate retry —
/// the failed-attempt path never poisons the key.
#[tokio::test]
async fn release_on_failure_frees_the_key_for_a_legitimate_retry() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire_or_check call");
    let AcquireOutcome::Acquired { record_id } = first else {
        panic!("expected Acquired for a brand-new identity");
    };

    release_on_failure(&state, record_id).await;

    let retry = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("retry acquire_or_check call after release");
    assert!(
        matches!(retry, AcquireOutcome::Acquired { .. }),
        "a released record must let a fresh attempt acquire the identity again, got a different outcome"
    );
}

/// The concurrent-acquire race the module doc names explicitly: two
/// simultaneous `acquire_or_check` calls for the identical identity must
/// have exactly one winner (`Acquired`) — `INSERT ... ON CONFLICT DO
/// NOTHING`'s actual job. Uses two separate pool handles (mirroring two
/// concurrent requests each with their own connection) rather than sharing
/// one, so this genuinely exercises Postgres's own conflict resolution, not
/// just sequential calls on one connection.
#[tokio::test]
async fn concurrent_acquire_for_the_same_identity_has_exactly_one_winner() {
    let state_a = skip_if_no_db!(test_state().await);
    let mut state_b = skip_if_no_db!(test_state().await);
    // A second, independent pool handle. Taken after the two `skip_if_no_db!`
    // lines rather than before: those already returned from the test if there
    // is no throwaway database, so the URL is present by construction here
    // and needs no second skip/panic decision of its own.
    let db_url = attome_testkit::migrated_db_url().expect("test_state already bound a database");
    state_b.db = attome_testkit::connect(&db_url, attome_testkit::DEFAULT_MAX_CONNECTIONS).await;

    let (principal, method, operation, client_key) = random_identity(&state_a.db).await;

    let (result_a, result_b) = tokio::join!(
        acquire_or_check(
            &state_a,
            principal,
            method,
            &operation,
            &client_key,
            "hash-a"
        ),
        acquire_or_check(
            &state_b,
            principal,
            method,
            &operation,
            &client_key,
            "hash-a"
        ),
    );

    let outcomes = [result_a.expect("call A"), result_b.expect("call B")];
    let acquired_count = outcomes
        .iter()
        .filter(|o| matches!(o, AcquireOutcome::Acquired { .. }))
        .count();
    assert_eq!(
        acquired_count, 1,
        "exactly one of the two concurrent acquires must win, got {acquired_count}"
    );
}

/// D-207: the scenario `a_still_pending_record_reports_in_progress_not_a_
/// second_acquire` above proves is correct for a genuinely in-flight
/// request — but if the ORIGINAL request crashed (server killed, panic
/// before `complete_in_tx`/`release_on_failure` ever ran) rather than merely
/// being slow, that `pending` row must not stay `InProgress` forever. Backdate
/// `updated_at` past `STALE_PENDING_AFTER_MINUTES` (there is no seam to fake
/// the clock otherwise — this row IS the simulated crash) and confirm a retry
/// with the SAME identity + body_hash reclaims the identical record_id and
/// gets `Acquired`, i.e. the caller actually re-runs the operation instead of
/// being told to wait on a request that is never coming back.
#[tokio::test]
async fn a_stale_pending_record_past_the_threshold_is_reclaimed_not_stuck_forever() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire_or_check call");
    let AcquireOutcome::Acquired {
        record_id: original_record_id,
    } = first
    else {
        panic!("expected Acquired for a brand-new identity");
    };

    // Simulate the crash: the original request never called complete_in_tx,
    // complete_best_effort, or release_on_failure, and enough time has now
    // passed that this row is plainly abandoned, not merely slow.
    sqlx::query(
        "UPDATE idempotency_record SET updated_at = NOW() - INTERVAL '10 minutes' \
         WHERE id = $1",
    )
    .bind(original_record_id)
    .execute(&state.db)
    .await
    .expect("backdate updated_at to simulate a stale pending record");

    let retry = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("retry acquire_or_check call against the stale pending record");
    let AcquireOutcome::Acquired { record_id } = retry else {
        let outcome_name = match retry {
            AcquireOutcome::Replay(_) => "Replay",
            AcquireOutcome::InProgress => "InProgress",
            AcquireOutcome::DifferentRequest => "DifferentRequest",
            AcquireOutcome::Acquired { .. } => unreachable!(),
        };
        panic!("expected a stale pending record to be reclaimed as Acquired, got {outcome_name}");
    };
    assert_eq!(
        record_id, original_record_id,
        "a reclaim must reuse the existing record's id, not mint a new row"
    );
}

/// A stale pending record must only be reclaimable by a retry carrying the
/// SAME `body_hash` — a differing hash under a still-stale key is a
/// different logical request reusing the key, and must be rejected as
/// `DifferentRequest`, never silently allowed to take over and run in place
/// of the original (abandoned) attempt's content.
#[tokio::test]
async fn a_stale_pending_record_with_a_different_body_hash_is_still_rejected() {
    let state = skip_if_no_db!(test_state().await);
    let (principal, method, operation, client_key) = random_identity(&state.db).await;

    let first = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-a")
        .await
        .expect("first acquire_or_check call");
    assert!(matches!(first, AcquireOutcome::Acquired { .. }));

    sqlx::query(
        "UPDATE idempotency_record \
         SET updated_at = NOW() - INTERVAL '10 minutes' \
         WHERE principal_ref = $1 AND http_method = $2 AND operation = $3 AND client_key = $4",
    )
    .bind(principal)
    .bind(method)
    .bind(&operation)
    .bind(&client_key)
    .execute(&state.db)
    .await
    .expect("backdate updated_at to simulate a stale pending record");

    let retry = acquire_or_check(&state, principal, method, &operation, &client_key, "hash-b")
        .await
        .expect("retry acquire_or_check call with a different body_hash");
    assert!(
        matches!(retry, AcquireOutcome::DifferentRequest),
        "a stale pending record with a mismatched body_hash must never be silently reclaimed"
    );
}

async fn complete(state: &AppState, record_id: Uuid, body: &[u8]) {
    let mut tx = state.db.begin().await.expect("begin tx");
    complete_in_tx(&mut tx, record_id, None, 201, &[], body)
        .await
        .expect("complete_in_tx");
    tx.commit().await.expect("commit");
}

fn outcome_name(outcome: &AcquireOutcome) -> &'static str {
    match outcome {
        AcquireOutcome::Acquired { .. } => "Acquired",
        AcquireOutcome::Replay(_) => "Replay",
        AcquireOutcome::InProgress => "InProgress",
        AcquireOutcome::DifferentRequest => "DifferentRequest",
    }
}

/// Phase 1 security acceptance: the durable identity includes the principal.
/// A second principal using the first one's operation, client key and body
/// hash — while the first record is pending, and after it completed — acquires
/// its own record, and each principal replays only its own response. A third
/// principal with a different body hash is also a fresh acquire, not
/// `DifferentRequest` against another principal's record.
#[tokio::test]
async fn a_durable_key_is_scoped_to_its_principal() {
    let state = skip_if_no_db!(test_state().await);
    let (principal_a, method, operation, client_key) = random_identity(&state.db).await;
    let principal_b = seed_throwaway_user(&state.db).await;
    let principal_c = seed_throwaway_user(&state.db).await;

    let acquire = |principal: Uuid, body_hash: &'static str| {
        let (state, operation, client_key) = (&state, &operation, &client_key);
        async move {
            acquire_or_check(state, principal, method, operation, client_key, body_hash)
                .await
                .expect("acquire_or_check")
        }
    };

    let AcquireOutcome::Acquired {
        record_id: record_a,
    } = acquire(principal_a, "hash-a").await
    else {
        panic!("A's first use of the key must acquire");
    };
    let b_first = acquire(principal_b, "hash-a").await;
    let AcquireOutcome::Acquired {
        record_id: record_b,
    } = b_first
    else {
        panic!(
            "B must acquire its own record while A's is pending, got {}",
            outcome_name(&b_first)
        );
    };
    assert_ne!(record_a, record_b);

    complete(&state, record_a, b"from-a").await;
    complete(&state, record_b, b"from-b").await;

    for (principal, expected) in [(principal_a, b"from-a"), (principal_b, b"from-b")] {
        match acquire(principal, "hash-a").await {
            AcquireOutcome::Replay(cached) => assert_eq!(cached.body, expected),
            other => panic!("expected Replay, got {}", outcome_name(&other)),
        }
    }

    let c_first = acquire(principal_c, "hash-b").await;
    assert!(
        matches!(c_first, AcquireOutcome::Acquired { .. }),
        "a different principal with a different body must acquire, got {}",
        outcome_name(&c_first)
    );
}
