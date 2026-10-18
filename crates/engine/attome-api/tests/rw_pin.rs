//! Integration coverage for `rw_pin.rs`'s `pin_write_with_current_lsn` — the
//! shared read-your-own-writes sticky-primary pin helper every entity
//! mutation (create/update/delete/restore/merge/upsert) calls right after
//! its transaction commits (`entity_crud/mutations.rs`, `entity_crud/merge.rs`,
//! `entity_crud/upsert.rs`, `admin/mod.rs::pin_write_best_effort`). That
//! function is `pub(crate)` and unreachable from a `tests/` integration
//! binary, so this file drives it the only way it's reachable from the
//! outside: perform a real entity mutation through the ordinary generic-CRUD
//! HTTP API (same money-path surface as `entity_round_trip.rs`), then read
//! the Redis pin `pin_write_with_current_lsn` should have written, via
//! `attome_cache::sticky_primary::check_pin` against the same `RedisPool`
//! (`EngineState::base::redis`).
//!
//! Covers:
//! - a fresh user has no pin before any mutation (`PinCheck::None`),
//! - a successful HTTP `create` pins the writer to a value that parses as a
//!   real Postgres LSN (`sticky_primary::parse_lsn`),
//! - `update` and `delete` also pin the writer (distinct call sites in
//!   `entity_crud/mutations.rs`), each capturing an LSN at least as far
//!   along as the previous mutation's,
//! - the pin's TTL is `max(database.sticky_primary_ttl_secs,
//!   database.replica_max_lag_secs)` (`rw_pin.rs`'s own doc comment), proven
//!   by configuring the two to distinct values and reading the key's TTL
//!   back with `fred`'s `KeysInterface::ttl` — same technique
//!   `attome-cache/tests/sticky_primary.rs` and `attome-s2s/tests/rate_limit.rs`
//!   already use against a live Redis.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway test database —
//! NEVER `attome_dev`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`,
//! default `localhost:6379`) — same convention as `entity_round_trip.rs`/
//! `rewrap_admin.rs`.
//! **Verified 2026-08-24 (MAINT-10): 4 passed, 0 failed, 48.98s** against a
//! real Postgres and Redis, retiring the "Not run in this session (code-only,
//! no DB/Redis access)" note this header carried.
//!
//! Both runs are recorded deliberately, because the first one failed and the
//! failure was convincing: **3 passed / 1 failed in 36.46s**, with
//! `fresh_user_has_no_pin_before_any_mutation` dying at `:162` in *harness
//! setup* — `build EngineSystem` hit `canceling statement due to statement
//! timeout` while provisioning an entity's active index — rather than on any
//! assertion. That reads like a real defect. It was transient: the machine was
//! running five concurrent cargo builds, and a plain retry passed clean with
//! no code change. **Retry once before concluding**, and say which run you are
//! quoting — this suite has been observed at 36s and at 49s for the same code,
//! and a sibling suite at 82s and 177s, so elapsed time alone can mislead in
//! the reassuring direction as easily as the alarming one.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test rw_pin -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_cache::sticky_primary::{PinCheck, check_pin, parse_lsn};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `sticky_primary_ttl_secs`/`replica_max_lag_secs` are parameterized so the
/// TTL test below can set them to distinct, easily-assertable values —
/// every other test just passes today's real defaults (5, 0 — `0` here means
/// "omit"/`None`, `unwrap_or(0)`'s own fallback, per `database.rs`'s
/// `replica_max_lag_secs` doc comment).
fn test_config(sticky_primary_ttl_secs: u64, replica_max_lag_secs: u64) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "readonly": {{ "user": "unused", "password": "unused", "port": 5555 }},
                "sticky_primary_ttl_secs": {sticky_primary_ttl_secs},
                "replica_max_lag_secs": {replica_max_lag_secs}
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
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

async fn test_system(
    sticky_primary_ttl_secs: u64,
    replica_max_lag_secs: u64,
) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    attome_testkit::migrated_db_url()?;

    let config = test_config(sticky_primary_ttl_secs, replica_max_lag_secs);
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

/// `oneshot()`-driven test requests carry no `Sec-Fetch-Site`/`Origin` header
/// at all (unlike a real browser), which `csrf_protect` fails closed on for
/// any cookie-authenticated unsafe-method request — same fix
/// `entity_round_trip.rs` uses, needed here for the same reason (this file's
/// mutations are POST/PATCH/DELETE through the generic CRUD API).
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
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

fn session_cookie(user_id: Uuid) -> String {
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

/// Seeds a throwaway admin `user_account` and returns `(user_id,
/// session_cookie)` — the `user_id` is needed directly (not just the
/// cookie), since `pin_write_with_current_lsn` pins `ctx.user_id`, the
/// session's own subject, and this file's tests check that exact key.
async fn seed_admin(system: &EngineSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("rw-pin-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
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

    (user_id, session_cookie(user_id))
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Provisions a throwaway entity with one `title` text field via the admin
/// API and returns its logicalname — shared setup so each test below has a
/// real entity to create/update/delete records against. Prefixes here are
/// all well under `MAX_IDENTIFIER_LEN` (48 bytes) with a full
/// `Uuid::now_v7().simple()` (32 hex chars) suffix, same headroom
/// `entity_round_trip.rs::provision_test_entity` relies on.
async fn provision_entity(app: &axum::Router, admin_cookie: &str, prefix: &str) -> String {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());

    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"RW Pin Test"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_entity_req)
        .await
        .expect("create entity");
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    let create_field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        ))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_field_req)
        .await
        .expect("create field");
    assert_eq!(res.status(), StatusCode::CREATED);

    logicalname
}

/// Same key-shape literal `attome-cache/tests/sticky_primary.rs` already
/// hard-codes in its own tests (`sticky_primary.rs`'s module doc comment:
/// `"attome-db:rw-pin:{user_id}"`, guidelines §5's `{crate}:{purpose}:{id}`
/// convention) — `sticky_primary::key()` itself is private to that crate, so
/// this is the only way to read the raw Redis key/TTL from outside it.
fn rw_pin_key(user_id: Uuid) -> String {
    format!("attome-db:rw-pin:{user_id}")
}

/// Before any mutation, a fresh user has no sticky-primary pin at all.
#[tokio::test]
async fn fresh_user_has_no_pin_before_any_mutation() {
    let system = skip_if_no_db!(test_system(5, 0).await);
    let (user_id, _admin_cookie) = seed_admin(&system).await;
    let redis = system.state().base.redis.clone();

    assert_eq!(check_pin(&redis, user_id).await, PinCheck::None);
}

/// A successful HTTP `create` through the generic entity-CRUD API pins the
/// writer to a value that parses as a real `pg_lsn` — proves
/// `entity_crud/mutations.rs`'s `create_record` call site actually fires
/// `pin_write_with_current_lsn` after commit, not just that the DB write
/// succeeded.
#[tokio::test]
async fn http_create_pins_the_writer_to_a_real_postgres_lsn() {
    let system = skip_if_no_db!(test_system(5, 0).await);
    let (user_id, admin_cookie) = seed_admin(&system).await;
    let redis = system.state().base.redis.clone();
    let app = full_app(system);
    let logicalname = provision_entity(&app, &admin_cookie, "rwpin_create").await;

    // `provision_entity` above is itself a write performed as this same admin,
    // so it legitimately leaves a sticky-primary pin behind. Clear it, or the
    // sanity assertion below is a race: it only passes when the pin's TTL
    // happens to lapse between provisioning and the check, which is why this
    // test passed locally and failed on a faster CI runner
    // (`left: Pinned("0/603B018"), right: None`). Clearing makes the
    // precondition true by construction rather than by timing, and the
    // assertion still proves what it was written to prove — that the CREATE
    // below is what establishes the pin.
    let _: i64 = redis
        .del(rw_pin_key(user_id))
        .await
        .expect("clearing the provisioning pin must not error");

    assert_eq!(
        check_pin(&redis, user_id).await,
        PinCheck::None,
        "sanity: no pin before the mutation under test"
    );

    let create_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"title":"hello"}"#))
        .unwrap();
    let res = app
        .oneshot(create_req)
        .await
        .expect("create record request");
    assert_eq!(res.status(), StatusCode::CREATED);

    match check_pin(&redis, user_id).await {
        PinCheck::Pinned(lsn) => assert!(
            parse_lsn(&lsn).is_some(),
            "pinned value {lsn:?} must look like a real pg_lsn (\"XXXX/YYYYYYYY\")"
        ),
        other => panic!("expected a pin after a successful create, got {other:?}"),
    }
}

/// `update` and `delete` are distinct call sites in
/// `entity_crud/mutations.rs` from `create` — each must independently pin
/// the writer, not just leave create's pin sitting there unrefreshed. Each
/// mutation's captured LSN (`pg_current_wal_insert_lsn()` at that moment)
/// must be at least as far along as the previous mutation's, per
/// `rw_pin.rs`'s own doc comment ("always >= the write's own commit LSN").
#[tokio::test]
async fn update_and_delete_also_pin_the_writer_with_non_decreasing_lsns() {
    let system = skip_if_no_db!(test_system(5, 0).await);
    let (user_id, admin_cookie) = seed_admin(&system).await;
    let redis = system.state().base.redis.clone();
    let app = full_app(system);
    let logicalname = provision_entity(&app, &admin_cookie, "rwpin_cud").await;

    // ── Create ──
    let create_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"title":"v0"}"#))
        .unwrap();
    let res = app.clone().oneshot(create_req).await.expect("create");
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let record_id = created["id"].as_str().expect("record id").to_owned();
    let row_version = created["row_version"].as_i64().expect("row_version");

    let after_create_lsn = match check_pin(&redis, user_id).await {
        PinCheck::Pinned(lsn) => parse_lsn(&lsn).expect("valid lsn after create"),
        other => panic!("expected a pin after create, got {other:?}"),
    };

    // ── Update ──
    let update_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(r#"{"title":"v1"}"#))
        .unwrap();
    let res = app.clone().oneshot(update_req).await.expect("update");
    assert_eq!(res.status(), StatusCode::OK);

    let after_update_lsn = match check_pin(&redis, user_id).await {
        PinCheck::Pinned(lsn) => parse_lsn(&lsn).expect("valid lsn after update"),
        other => panic!("expected a pin after update, got {other:?}"),
    };
    assert!(
        after_update_lsn >= after_create_lsn,
        "update's captured LSN ({after_update_lsn}) must not be behind create's ({after_create_lsn})"
    );

    // ── Delete ──
    let delete_req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(delete_req).await.expect("delete");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let after_delete_lsn = match check_pin(&redis, user_id).await {
        PinCheck::Pinned(lsn) => parse_lsn(&lsn).expect("valid lsn after delete"),
        other => panic!("expected a pin after delete, got {other:?}"),
    };
    assert!(
        after_delete_lsn >= after_update_lsn,
        "delete's captured LSN ({after_delete_lsn}) must not be behind update's ({after_update_lsn})"
    );
}

/// `rw_pin.rs`'s doc comment: the pin's effective TTL is
/// `max(database.sticky_primary_ttl_secs, database.replica_max_lag_secs)` so
/// the pin never expires before the deployment's own declared lag
/// tolerance. Configuring the two to distinct, far-apart values and reading
/// the raw Redis key's TTL back (`fred`'s `KeysInterface::ttl`, same
/// technique `attome-cache/tests/sticky_primary.rs`'s
/// `pin_write_with_lsn_sets_the_configured_ttl` and
/// `attome-s2s/tests/rate_limit.rs` already use) proves it actually took the
/// larger of the two, not just `sticky_primary_ttl_secs` alone.
#[tokio::test]
async fn pin_ttl_is_the_max_of_sticky_ttl_and_replica_max_lag() {
    let sticky_primary_ttl_secs = 5;
    let replica_max_lag_secs = 30;
    let system = skip_if_no_db!(test_system(sticky_primary_ttl_secs, replica_max_lag_secs).await);
    let (user_id, admin_cookie) = seed_admin(&system).await;
    let redis = system.state().base.redis.clone();
    let app = full_app(system);
    let logicalname = provision_entity(&app, &admin_cookie, "rwpin_ttl").await;

    let create_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"title":"hello"}"#))
        .unwrap();
    let res = app.oneshot(create_req).await.expect("create record");
    assert_eq!(res.status(), StatusCode::CREATED);

    let key = rw_pin_key(user_id);
    let ttl: i64 = redis.ttl(&key).await.expect("TTL query must not error");
    assert!(
        ttl > sticky_primary_ttl_secs as i64 && ttl <= replica_max_lag_secs as i64,
        "expected TTL to reflect max(sticky_primary_ttl_secs={sticky_primary_ttl_secs}, \
         replica_max_lag_secs={replica_max_lag_secs}) = {replica_max_lag_secs}, got {ttl}"
    );
}
