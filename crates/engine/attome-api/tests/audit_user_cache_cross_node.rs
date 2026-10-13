//! Cross-node invalidation for `EngineState::audit_users` (the denormalized
//! `user_account` display-name/email/organization_ref fields cached
//! for `AuditEvent.user_context`, `attome-core/src/state.rs`) — closes a
//! deferred code-review finding: a user's display-name/email edit handled by
//! one node used to stay invisible to every OTHER node's L1 for up to the
//! 60s TTL (cosmetic — denormalized display fields only, never the audit
//! hash chain itself — but no longer just "self-heals eventually").
//!
//! `EngineState::invalidate_audit_user` (state.rs) now purges the local entry
//! and best-effort publishes on `AUDIT_USER_VERSION_CHANNEL`; the dedicated
//! subscriber wired in `attome-api/src/system.rs`'s `EngineSystemBuilder::build()`
//! calls `invalidate_audit_user_local` on every OTHER node as soon as the
//! message arrives. `entity_crud.rs`'s `update_record`/`delete_record` call
//! this post-commit (never inside the mutation's own transaction, per
//! guidelines §4) whenever the mutated entity is `user_account`
//! itself; `bulk.rs`'s two equivalent real-commit sites do the same.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`, defaulting to `localhost:6379`) —
//! same convention as `authz_revocation_cross_node.rs`; NOT wired into any
//! CI run yet (no `attomedb_test` harness — see P1.8). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test audit_user_cache_cross_node -- --test-threads=1
//! ```
//!
//! NOTE: authored and reviewed against the code, but **not executed** in the
//! environment this fix was written in (no Postgres/Redis/cargo toolchain
//! available there — see the repo's `no_rust_toolchain` note). Run it for
//! real, per the command above, before relying on it as a passing regression
//! test.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::time::{Duration, Instant};

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::{AuditUserInfo, EngineState, audit_user_cache_key};
use attome_server::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config() -> AppConfig {
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Builds one independent "node" — its own `EngineState`/registry/subscribers,
/// including the `audit_user_version` one wired in `system.rs` — sharing the
/// same Postgres + Redis as every other node built this way. Mirrors
/// `authz_revocation_cross_node.rs::test_node`.
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

fn session_cookie_for(user_id: Uuid) -> String {
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

async fn seed_bare_user(db: &attome_db::DbPool, label: &str) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("{label}-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Seeds a throwaway admin user (direct `system.admin` grant, same as
/// `authz_revocation_cross_node.rs::seed_admin`) and its session cookie —
/// `system.admin` short-circuits `ctx.require()` for every entity including
/// `user_account` itself (D-012's comment on `entity_crud.rs`), so
/// this one identity can PATCH any user's row in these tests.
async fn seed_admin(db: &attome_db::DbPool) -> String {
    let user_id = seed_bare_user(db, "audit-cache-cross-node-admin").await;
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
    .expect("insert throwaway direct admin grant");
    session_cookie_for(user_id)
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Polls `state.audit_users` for `key` until it's absent or `bound` elapses.
/// Real cross-process Redis pub/sub delivery is normally sub-10ms on a local
/// connection, but unlike `strict_authz`'s forced re-check (which the
/// authz-revocation cross-node tests lean on for a single-retry assertion),
/// `audit_users` has no per-read live check to fall back on — this cache is
/// purely best-effort pub/sub plus the pre-existing 60s TTL, so proving the
/// fix means actually waiting (briefly, boundedly) for the message to land.
async fn poll_until_absent(state: &EngineState, key: &str, bound: Duration) -> bool {
    let started = Instant::now();
    loop {
        if state.audit_users.get(key).await.is_none() {
            return true;
        }
        if started.elapsed() >= bound {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Mechanism-level proof: two independently-built `EngineSystem` nodes (each
/// with its own `audit_user_version` subscriber wired by `system.rs`),
/// sharing one Postgres + Redis. Node B is warmed with a stale cache entry
/// (simulating an earlier `fetch_audit_ctx` DB read); node A calls the exact
/// method `entity_crud.rs`'s post-commit hook calls in production
/// (`EngineState::invalidate_audit_user`). Node B's own local entry must be
/// gone shortly after, without node B ever being told directly — proving the
/// publish from A actually reaches B's subscriber and purges its L1.
#[tokio::test]
async fn invalidate_audit_user_propagates_to_other_nodes() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let user_id = seed_bare_user(&db, "audit-cache-cross-node-subject").await;
    let key = audit_user_cache_key(user_id);

    node_b
        .state()
        .audit_users
        .insert(
            key.clone(),
            AuditUserInfo {
                user_name: Some("Stale Name".into()),
                email: Some("stale@example.test".into()),
                organization_ref: None,
            },
        )
        .await;
    assert!(
        node_b.state().audit_users.get(&key).await.is_some(),
        "test setup: node B's cache must be warmed before invalidation"
    );

    node_a.state().invalidate_audit_user(user_id).await;

    assert!(
        poll_until_absent(node_b.state(), &key, Duration::from_secs(5)).await,
        "node B's audit_users entry for {user_id} must be purged by the \
         audit_user_version subscriber within 5s of node A's invalidate_audit_user, \
         not only after the 60s TTL"
    );
}

/// End-to-end proof through the real production path: PATCHing
/// `user_account`'s `user_name`/`email` via node A's HTTP API (the
/// exact `entity_crud.rs::update_record` handler, gated the same as any
/// other entity update) must invalidate node B's independently-warmed
/// `audit_users` entry for that same user, without node B ever seeing the
/// PATCH request itself.
#[tokio::test]
async fn systemuser_update_via_one_node_invalidates_audit_cache_on_another() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let subject_id = seed_bare_user(&db, "audit-cache-cross-node-target").await;
    let admin_cookie = seed_admin(&db).await;
    let key = audit_user_cache_key(subject_id);

    // Warm node B as if it had recently written an audit event authored by
    // this user (the real `fetch_audit_ctx` path this cache actually serves).
    node_b
        .state()
        .audit_users
        .insert(
            key.clone(),
            AuditUserInfo {
                user_name: Some("Old Display Name".into()),
                email: Some("old@example.test".into()),
                organization_ref: None,
            },
        )
        .await;

    let app_a = full_app(node_a);

    let row_version: i64 = sqlx::query_scalar("SELECT row_version FROM user_account WHERE id = $1")
        .bind(subject_id)
        .fetch_one(&db)
        .await
        .expect("fetch seeded row_version");

    // Per-run unique, not a hardcoded `new@example.test`: this PATCH is the one
    // value in this suite that actually reaches the database (the two
    // `AuditUserInfo` emails above only warm an in-memory cache), and
    // `user_account` has a unique index on `email`. A fixed address
    // therefore succeeds on a fresh database and 409s on every rerun against
    // the same one — `conflict: unique constraint violated`, which is the
    // `core_systemuser_email_unique` collision class of F-006/TODO-008(c).
    // What this test asserts is cache invalidation; the address is incidental.
    let new_email = attome_testkit::unique_email("audit-cache-cross-node");
    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/user_account/{subject_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(format!(
            r#"{{"user_name":"New Display Name","email":"{new_email}"}}"#
        )))
        .unwrap();
    let res = app_a.oneshot(patch_req).await.expect("patch user_account");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "systemuser PATCH must succeed, got {status}: {body}"
    );

    assert!(
        poll_until_absent(node_b.state(), &key, Duration::from_secs(5)).await,
        "node B's audit_users entry for {subject_id} must be purged within 5s of \
         node A's systemuser PATCH committing, not only after the 60s TTL"
    );
}
