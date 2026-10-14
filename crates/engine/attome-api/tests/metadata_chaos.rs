//! CONC-6 — the metadata registry under node failure. `metadata_cache.rs`
//! proves the happy path (a write on node A reaches node B through the
//! `meta_version` doorbell). This file kills the writer at each point where a
//! crash leaves a *different* durable state behind, and proves the recovery
//! path documented in `attome-api/src/system.rs` — change log + watermark
//! poll + snapshot pre-warm — actually closes each one:
//!
//! | crash window                          | durable state left behind                      | recovery path under test          |
//! |---------------------------------------|------------------------------------------------|-----------------------------------|
//! | mid-transaction, before commit        | an orphaned session holding the write lock     | Postgres aborts it on socket loss |
//! | after commit, before the doorbell     | a change-log row nobody was told about         | the 5s watermark poll             |
//! | a subscriber mid-catch-up             | a Redis snapshot behind the change log         | `pre_warm_registry`'s catch-up    |
//! | Postgres restored under a live Redis  | a Redis snapshot *ahead of* the change log     | `pre_warm_registry`'s inversion   |
//!
//! # "Kill a node" is simulated at the durable-state level, on purpose
//!
//! Every node here is an in-process `EngineSystem` sharing one Postgres and one
//! Redis, the same harness `metadata_cache.rs` uses. A process kill
//! (`audit_chainer_process_kill.rs`'s technique) would need the `server`
//! binary and would still only produce one of the four states above per run,
//! non-deterministically. Producing each state directly — an abruptly
//! closed socket, the engine's own write primitive with the publish step
//! omitted, a snapshot rewritten behind or ahead of the log — is both
//! deterministic and *exactly* what a crash leaves on disk, because the
//! platform's write path is one transaction followed by one best-effort
//! PUBLISH, and a crashed process leaves nothing else.
//!
//! # Runtime
//!
//! `committed_write_whose_doorbell_never_fired_is_recovered_by_the_watermark_poll`
//! takes ~5s: `cache.metadata_poll_interval_secs` defaults to 5 (Y8-T2), and
//! the test waits for a real tick. That is the cost of proving the poll and
//! not a mock of it.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`); skips loudly without them, same as `metadata_cache.rs`:
//!
//! ```powershell
//! cargo test -p attome-api --test metadata_chaos -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_metadata::provision::{self, AttributeDesc, EntityDesc, ReconcilePolicy};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::{Connection, PgConnection};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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
            "security": {{ "bootstrap_admin_email": null }}
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

/// One independent "node" — its own registry, subscriber and watermark
/// poller — sharing Postgres + Redis with every other node built this way.
/// Identical to `metadata_cache.rs::test_node`.
async fn test_node() -> Option<EngineSystem> {
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

    let system = EngineSystem::builder(state)
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
    Some(system)
}

/// See `metadata_cache.rs::stamp_test_origin` — `csrf_protect` needs a safe
/// `Sec-Fetch-Site` on cookie-authenticated unsafe methods.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    req
}

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
}

async fn seed_admin(system: &EngineSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("metadata-chaos-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind("system.admin")
        .fetch_one(db)
        .await
        .expect("system.admin privilege must already be seeded by attome_security::seed::seed");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway admin grant");

    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: "attome-test".into(),
        aud: "attome-test".into(),
        typ: attome_auth::TokenType::Session,
    };
    let signing_ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &signing_ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// `POST /api/v1/admin/entities` through the real handler — the write path
/// that takes the metadata lock, appends the change log, commits, and only
/// then publishes the doorbell.
async fn create_entity_via_api(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
) -> (StatusCode, Option<Uuid>) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Metadata Chaos Test"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("create entity request");
    let status = res.status();
    if status != StatusCode::CREATED {
        return (status, None);
    }
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read create-entity body");
    let entity: serde_json::Value = serde_json::from_slice(&bytes).expect("create-entity JSON");
    let id = entity["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("create-entity response carries an id");
    (status, Some(id))
}

/// Adds the one text field every chaos entity carries, through the admin
/// API (a second metadata write, second change-log row, second doorbell).
async fn create_note_field_via_api(app: &axum::Router, cookie: &str, entity_id: Uuid) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"note","name":"Note","field_type":"text"}"#,
        ))
        .unwrap();
    let status = app
        .clone()
        .oneshot(req)
        .await
        .expect("create field request")
        .status();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "note field creation must succeed"
    );
}

/// The same field, written with the engine primitive the admin handler
/// calls — no doorbell, for the crash window that never reaches one.
async fn provision_note_field(db: &attome_db::DbPool, entity_id: Uuid) {
    provision::reconcile_attribute(
        db,
        entity_id,
        &AttributeDesc {
            logicalname: "note".into(),
            display_name: "Note".into(),
            field_type: "text".into(),
            is_required: false,
            is_sensitive: false,
            is_write_restricted: None,
            is_sortable: false,
            is_filterable: false,
            lookup_entity: None,
            options: None,
            max_length: None,
            on_target_delete: None,
            data_classification: None,
            purpose: None,
        },
        ReconcilePolicy::Admin,
    )
    .await
    .expect("commit the note field on the crashing node");
}

/// Whether this node's registry knows `logicalname` *right now*. Same probe
/// `metadata_cache.rs` uses: a record `POST` resolves the entity from the
/// in-memory registry, so a 404 is "this node has not applied the change
/// yet" and a 201 is "it has, and the schema it applied is usable". Never
/// consults Postgres for the schema, which is what makes it a probe of the
/// registry rather than of the database.
async fn registry_knows(app: &axum::Router, cookie: &str, logicalname: &str) -> bool {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"note":"registry probe"}"#))
        .unwrap();
    let status = app
        .clone()
        .oneshot(req)
        .await
        .expect("record create request")
        .status();
    assert!(
        status == StatusCode::CREATED || status == StatusCode::NOT_FOUND,
        "registry probe for {logicalname} returned {status}, expected 201 (known) or 404 (unknown)"
    );
    status == StatusCode::CREATED
}

/// Polls `registry_knows` until true or `deadline` elapses; returns how long
/// it took, so a caller can report *which* recovery path plausibly fired.
async fn wait_until_registry_knows(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    deadline: Duration,
) -> Option<Duration> {
    let started = tokio::time::Instant::now();
    loop {
        if registry_knows(app, cookie, logicalname).await {
            return Some(started.elapsed());
        }
        if started.elapsed() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn fresh_logicalname() -> String {
    format!("mchaos_{}", Uuid::now_v7().simple())
}

// ── Crash window 1: mid-transaction, before commit ─────────────────────────

/// A writer that dies holding the global metadata-write lock must not wedge
/// every subsequent metadata write behind a 409. The lock is
/// `pg_try_advisory_xact_lock` on the writer's own transaction, so the only
/// thing that can release it is that transaction ending — which, for a
/// crashed process, means Postgres noticing the dropped socket and aborting
/// it. This proves that happens, and that nothing in the platform (a pooled
/// connection, a keepalive) keeps the orphaned session alive past the crash.
///
/// The 409 *before* the kill is load-bearing: without it, a green result
/// could mean the lock was never held at all.
#[tokio::test]
async fn crash_before_commit_releases_the_metadata_write_lock() {
    let node_a = skip_if_no_db!(test_node().await);
    let cookie_a = seed_admin(&node_a).await;
    let app_a = full_app(node_a);
    let logicalname = fresh_logicalname();

    // A second "process": its own raw connection, not the node's pool, so
    // closing it hard is the crash and nothing else can tidy up after it.
    let url =
        attome_testkit::migrated_db_url().expect("skip_if_no_db already checked DATABASE_URL");
    let mut victim = PgConnection::connect(&url)
        .await
        .expect("open the crashing writer's own connection");
    let mut tx = victim.begin().await.expect("BEGIN on the crashing writer");
    attome_core::acquire_metadata_write_lock(&mut tx)
        .await
        .expect("the metadata write lock must be free before the crash is staged");

    assert_eq!(
        create_entity_via_api(&app_a, &cookie_a, &logicalname)
            .await
            .0,
        StatusCode::CONFLICT,
        "while the in-flight writer is alive its lock must refuse a concurrent metadata write"
    );

    // The crash: drop the socket without COMMIT, ROLLBACK, or Terminate.
    // `forget` keeps sqlx from queueing a polite ROLLBACK on drop — a real
    // crash sends nothing.
    std::mem::forget(tx);
    victim
        .close_hard()
        .await
        .expect("hard-close the crashing writer's socket");

    // Postgres aborts the orphaned transaction when it sees the socket go;
    // the advisory xact lock goes with it. Poll — the abort is asynchronous
    // to this test, but bounded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status = create_entity_via_api(&app_a, &cookie_a, &logicalname)
            .await
            .0;
        if status == StatusCode::CREATED {
            break;
        }
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "unexpected status while waiting for the orphaned lock to clear"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the crashed writer's metadata lock was never released — every later metadata \
             write on this deployment would 409 until the orphaned backend is killed by hand"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Crash window 2: after commit, before the doorbell ───────────────────────

/// The write path is one transaction (lock → metadata rows → change-log row
/// → COMMIT) followed by a best-effort `PUBLISH meta_version`
/// (`admin::notify_metadata_change`). A node killed between the two leaves a
/// committed change-log row that no subscriber was ever told about. Nothing
/// on node B fires: no message, no reconnect. The only thing that can find
/// the row is the periodic watermark poll (`system.rs`, `registry_
/// watermark_poll_forced_catchup_total`) comparing `log_watermark` against
/// what B last applied — this proves it does, on a real tick.
///
/// The write is performed with the exact engine primitive the admin handler
/// calls (`provision::reconcile_entity`) and node A is then dropped, so the
/// durable state is byte-for-byte what a crash at that point leaves.
///
/// **What a fast recovery means.** Redis pub/sub channels are global, not
/// per-database, so on a shared Redis a doorbell from an unrelated test
/// binary can wake B's subscriber early; B still recovers *from the log*, the
/// assertion still holds, and the elapsed time in the failure message says
/// which path most plausibly fired. On a quiet Redis — the deployment case
/// this exists for — only the poll can do it, and the test takes ~46s.
#[tokio::test]
async fn committed_write_whose_doorbell_never_fired_is_recovered_by_the_watermark_poll() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);
    let cookie_b = seed_admin(&node_b).await;
    let app_b = full_app(node_b);
    let logicalname = fresh_logicalname();

    assert!(
        !registry_knows(&app_b, &cookie_b, &logicalname).await,
        "a fresh logicalname must be unknown before the write"
    );

    // Node A's engine write path, up to and including COMMIT — and nothing
    // after it. This is where the crash lands.
    let db_a = node_a.state().base.db_migrator.clone();
    let (entity_id, _) = provision::reconcile_entity(
        &db_a,
        &EntityDesc {
            logicalname: logicalname.clone(),
            display_name: "Metadata Chaos Lost Doorbell".into(),
            primary_name_attribute: None,
            is_append_only: false,
            is_audited: false,
            category: None,
        },
        ReconcilePolicy::Admin,
    )
    .await
    .expect("commit the metadata write on node A");
    provision_note_field(&db_a, entity_id).await;
    drop(node_a); // the crash — A never reaches notify_metadata_change

    let db_watermark = attome_core::log_watermark(&db_a)
        .await
        .expect("read the change-log watermark");
    assert!(
        db_watermark > 0,
        "the committed write must have appended a change-log row for the poll to find"
    );

    // 5s poll interval (`cache.metadata_poll_interval_secs`) + 250ms debounce
    // + slack. Anything much longer hides a real regression behind the
    // deadline.
    let elapsed = wait_until_registry_knows(&app_b, &cookie_b, &logicalname, Duration::from_secs(30))
        .await
        .unwrap_or_else(|| {
            panic!(
                "node B never applied the doorbell-less write (change-log watermark {db_watermark}) \
                 within 30s — the watermark poll did not recover a lost PUBLISH, so a crash between \
                 COMMIT and the doorbell leaves every other node stale until an unrelated edit"
            )
        });
    eprintln!(
        "node B recovered the doorbell-less write after {elapsed:?} \
         ({})",
        if elapsed >= Duration::from_secs(4) {
            "consistent with the 5s watermark poll"
        } else {
            "faster than the poll interval — a doorbell from elsewhere on this Redis woke the subscriber; \
             recovery still came from the change log"
        }
    );
}

// ── Crash window 3: a subscriber killed mid-catch-up ────────────────────────

/// `catch_up` swaps the registry, advances `last_applied`, then saves the
/// Redis snapshot. A node killed between the swap and the save — or any node
/// restarting from a snapshot older than the change log — must not serve the
/// stale snapshot as truth. `pre_warm_registry` loads the snapshot and then
/// replays `changes_since(snapshot.log_id)`; this proves a restarted node is
/// current on its *first* request, with no doorbell and no poll involved.
///
/// The stale snapshot is written after node A has finished its own
/// catch-up (verified by A serving the entity), so A's post-catch-up
/// `save_snapshot` cannot land after the stale one and quietly repair it.
#[tokio::test]
async fn node_restarted_from_a_stale_snapshot_catches_up_at_pre_warm() {
    let node_a = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();
    let redis = node_a.state().base.redis.clone();
    let cookie_a = seed_admin(&node_a).await;

    // The world as a crashed subscriber last saw it.
    let stale_registry = (**node_a.state().entities.load()).clone();
    let stale_watermark = attome_core::log_watermark(&db)
        .await
        .expect("read the change-log watermark before the write");

    let app_a = full_app(node_a);
    let logicalname = fresh_logicalname();
    let (status, entity_id) = create_entity_via_api(&app_a, &cookie_a, &logicalname).await;
    assert_eq!(status, StatusCode::CREATED);
    create_note_field_via_api(&app_a, &cookie_a, entity_id.expect("201 carries an id")).await;
    wait_until_registry_knows(&app_a, &cookie_a, &logicalname, Duration::from_secs(10))
        .await
        .expect("node A must apply its own write (doorbell path) before the snapshot is rewound");

    // Rewind Redis to the pre-write world: exactly what a subscriber killed
    // after swapping its registry but before `save_snapshot` leaves behind.
    attome_core::save_snapshot(&redis, stale_watermark, &stale_registry)
        .await
        .expect("rewrite the registry snapshot to its pre-write state");

    // "Restart": a brand-new node pre-warms from that stale snapshot.
    let node_c = test_node()
        .await
        .expect("DATABASE_URL was present a moment ago");
    let cookie_c = seed_admin(&node_c).await;
    let app_c = full_app(node_c);
    assert!(
        registry_knows(&app_c, &cookie_c, &logicalname).await,
        "a node restarted from a snapshot behind the change log must catch up during pre-warm — \
         its first request served the stale snapshot as truth"
    );
}

// ── Crash window 4: Postgres restored underneath a live Redis ───────────────

/// The inversion `pre_warm_registry` guards against: a snapshot whose
/// watermark is *ahead of* the change log's current max id (Postgres
/// restored to an earlier point, Redis untouched). Trusting it would wedge
/// the node permanently — `changes_since(stale_id)` never finds anything
/// past an id the log will not reach for a long time — so the node must
/// discard the snapshot and rebuild from Postgres. Proven the same way:
/// current on the first request, no doorbell, no poll.
#[tokio::test]
async fn snapshot_ahead_of_the_database_forces_a_full_rebuild_at_pre_warm() {
    let node_a = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();
    let redis = node_a.state().base.redis.clone();
    let cookie_a = seed_admin(&node_a).await;

    let stale_registry = (**node_a.state().entities.load()).clone();

    let app_a = full_app(node_a);
    let logicalname = fresh_logicalname();
    let (status, entity_id) = create_entity_via_api(&app_a, &cookie_a, &logicalname).await;
    assert_eq!(status, StatusCode::CREATED);
    create_note_field_via_api(&app_a, &cookie_a, entity_id.expect("201 carries an id")).await;
    wait_until_registry_knows(&app_a, &cookie_a, &logicalname, Duration::from_secs(10))
        .await
        .expect("node A must apply its own write before the snapshot is corrupted");

    // A registry that does not know the entity, stamped with a watermark the
    // log cannot have reached: the state a restore drill leaves in Redis.
    let db_watermark = attome_core::log_watermark(&db)
        .await
        .expect("read the change-log watermark");
    attome_core::save_snapshot(&redis, db_watermark + 1_000_000, &stale_registry)
        .await
        .expect("write a snapshot ahead of the change log");

    let node_d = test_node()
        .await
        .expect("DATABASE_URL was present a moment ago");
    let cookie_d = seed_admin(&node_d).await;
    let app_d = full_app(node_d);
    assert!(
        registry_knows(&app_d, &cookie_d, &logicalname).await,
        "a node whose snapshot claims to be ahead of the change log must rebuild from Postgres — \
         it trusted the snapshot and would stay wedged behind an unreachable watermark"
    );
}

// ── Crash window 5: a snapshot naming an entity Postgres never had ─────────

/// The watermark comparison in crash window 4 only catches Redis running
/// *ahead* of Postgres. It says nothing when Postgres is swapped out from
/// under a live Redis (a dev volume reset, a restore into a differently-
/// seeded database) and the new database's own change log happens to reach
/// or pass the stale watermark on its own — exactly what happens the moment
/// the new database provisions its own entities and accumulates change-log
/// rows again from 1. A snapshot entry whose `entity_id` matches no row in
/// `entity_info` at all is the unambiguous signal that case leaves
/// behind, and it can't be produced by any in-order sequence of real writes
/// (`reconcile_entity` always `RETURNING id` from the row it just wrote or
/// found), so this stages it directly: a registry snapshot with one entry
/// naming a real logicalname against an `entity_id` nothing ever inserted.
///
/// A poisoned snapshot handed straight to a caller would reach exactly the
/// bug this test guards: `grant_creator_share`'s `record_share`
/// insert would violate its `entity_ref` foreign key on the very first
/// create against that logicalname.
#[tokio::test]
async fn snapshot_naming_an_entity_id_postgres_never_had_forces_a_full_rebuild_at_pre_warm() {
    let node_a = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();
    let redis = node_a.state().base.redis.clone();
    let cookie_a = seed_admin(&node_a).await;

    // A real entity, so the rebuild this test expects can be told apart from
    // an empty/failed one: it must still be there afterward.
    let app_a = full_app(node_a);
    let real_logicalname = fresh_logicalname();
    let (status, entity_id) = create_entity_via_api(&app_a, &cookie_a, &real_logicalname).await;
    assert_eq!(status, StatusCode::CREATED);
    create_note_field_via_api(&app_a, &cookie_a, entity_id.expect("201 carries an id")).await;
    wait_until_registry_knows(
        &app_a,
        &cookie_a,
        &real_logicalname,
        Duration::from_secs(10),
    )
    .await
    .expect("node A must apply its own write before the snapshot is poisoned");

    // The world as node A now honestly sees it (freshly rebuilt straight
    // from Postgres, so it's guaranteed to include the entity just created
    // above), plus one entry no write ever produced: a real-looking
    // logicalname mapped to an id that has no row in `entity_info`
    // at all — never behind, never ahead, simply never real. Saved at the
    // database's *current* watermark, not ahead of it, so crash window 4's
    // guard has nothing to catch here.
    let mut entities: Vec<attome_core::EntityMeta> = attome_core::build_registry(&db)
        .await
        .expect("rebuild a known-good registry to poison")
        .iter()
        .cloned()
        .collect();
    let ghost_logicalname = fresh_logicalname();
    entities.push(attome_core::EntityMeta {
        entity_id: Uuid::now_v7(),
        logicalname: ghost_logicalname.clone(),
        attrs: Vec::new(),
        is_append_only: false,
        primary_name_attribute: None,
    });
    let poisoned_registry = attome_core::EntityMetaRegistry::from_entities(entities);
    let db_watermark = attome_core::log_watermark(&db)
        .await
        .expect("read the change-log watermark");
    attome_core::save_snapshot(&redis, db_watermark, &poisoned_registry)
        .await
        .expect("write a snapshot naming a nonexistent entity id");

    // "Restart": a brand-new node pre-warms from that poisoned snapshot.
    let node_e = test_node()
        .await
        .expect("DATABASE_URL was present a moment ago");
    let cookie_e = seed_admin(&node_e).await;
    let app_e = full_app(node_e);

    assert!(
        !registry_knows(&app_e, &cookie_e, &ghost_logicalname).await,
        "a node that pre-warmed from a snapshot naming an entity id Postgres never had must \
         discard the whole snapshot and rebuild from Postgres — trusting it would hand the \
         next create on this logicalname an entity_id that fails grant_creator_share's \
         entity_ref foreign key"
    );
    assert!(
        registry_knows(&app_e, &cookie_e, &real_logicalname).await,
        "the rebuild triggered by the poisoned entry must still recover every entity that \
         really exists, not just discard the bad one and stop"
    );
}
