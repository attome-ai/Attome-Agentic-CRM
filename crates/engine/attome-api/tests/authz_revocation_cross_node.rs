//! Test #21: revocation across nodes and cache failures — HTTP-level leg.
//!
//! Drives the exact "authenticate via node A, warm node A/B, revoke via node
//! C, retry node A/B immediately" scenario through real `EngineSystem` nodes and
//! real `system.admin`-gated HTTP endpoints (`attome_security::admin::routes()`,
//! layered with `attome_security::strict_authz::strict_authz` per
//! `attome-api/src/system.rs`'s `core_routes`). The unit-level fail-closed /
//! restore-converge / unrelated-user / latency scenarios that don't need a
//! full router live in `crates/engine/attome-security/tests/resolver.rs`'s
//! "Test #21" section — `strict_authz` is a thin wrapper over exactly the
//! `SecurityCache::resolve_strict` call proven there, so this file only needs
//! to prove the HTTP wiring, not re-prove the cache mechanics.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`, defaulting to `localhost:6379`) —
//! skips (loudly) when `DATABASE_URL` is unset, except under `CI`, per the P1.8
//! testing-baseline convention. NOT wired into any CI run yet (no
//! `attomedb_test` harness exists — see P1.8); run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test authz_revocation_cross_node -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
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

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Builds one independent "node" — its own `EngineState`/registry/subscriber —
/// sharing the same Postgres + Redis as every other node built this way.
async fn test_node() -> Option<EngineSystem> {
    let db_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &db_url);
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
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));
    Some(system)
}

/// Same csrf_protect workaround as `metadata_cache.rs` — see its comment for
/// why Sec-Fetch-Site is the only viable signal for an in-process `oneshot()`
/// call against a `test_config()` with no `cors` section.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    req
}

/// Builds the full assembled app the same way `main.rs` does — see
/// `metadata_cache.rs`'s `full_app` doc for why `core_routes()` alone would
/// silently skip auth (in particular, the `strict_authz` layer this file's
/// tests depend on is applied inside `core_routes()`, not by `full_app`
/// itself).
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

/// Seeds a throwaway admin user (direct `system.admin` grant) and its session
/// cookie — mirrors `metadata_cache.rs`'s `seed_admin`, factored to reuse
/// `seed_bare_user`/`session_cookie_for` for the role/team-mediated variants
/// below.
async fn seed_admin(db: &attome_db::DbPool) -> String {
    let user_id = seed_bare_user(db, "authz-revocation-test-admin").await;
    grant_admin_directly(db, user_id).await;
    session_cookie_for(user_id)
}

async fn system_admin_privilege_id(db: &attome_db::DbPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
        .fetch_one(db)
        .await
        .expect("system.admin privilege must already be seeded by attome_security::seed::seed")
}

/// Grants `system.admin` directly to `user_id`. Returns the grant row id
/// (`user_account_mm_privilege.id`) for the DELETE-by-id revoke endpoint.
async fn grant_admin_directly(db: &attome_db::DbPool, user_id: Uuid) -> Uuid {
    let privilege_id = system_admin_privilege_id(db).await;
    let grant_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(grant_id)
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway direct admin grant");
    grant_id
}

/// Grants `system.admin` to `user_id` via a role (not a direct grant).
/// Returns the role id for the DELETE `/users/{id}/roles/{role_id}` endpoint.
async fn grant_admin_via_role(db: &attome_db::DbPool, user_id: Uuid) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("cross-node-admin-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");

    let privilege_id = system_admin_privilege_id(db).await;
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway role->privilege grant");

    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("insert throwaway user->role link");

    role_id
}

/// Grants `system.admin` to `user_id` via team membership (team holds the
/// admin role). Returns the team id for the DELETE
/// `/teams/{id}/members/{user_id}` endpoint.
async fn grant_admin_via_team(db: &attome_db::DbPool, user_id: Uuid) -> Uuid {
    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name, description) VALUES ($1, $2, $3)")
        .bind(team_id)
        .bind(format!("cross-node-admin-team-{team_id}"))
        .bind("throwaway test team")
        .execute(db)
        .await
        .expect("insert throwaway team");

    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("cross-node-admin-team-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");

    let privilege_id = system_admin_privilege_id(db).await;
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway role->privilege grant");

    sqlx::query("INSERT INTO role_mm_team (id, role_ref, team_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(team_id)
        .execute(db)
        .await
        .expect("insert throwaway role->team link");

    sqlx::query("INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(team_id)
        .execute(db)
        .await
        .expect("insert throwaway user->team link");

    team_id
}

/// The "protected operation" retried through each node: `system.admin` is a
/// coarse gate applied to every route in `attome_security::admin::routes()`
/// (see that module's header comment) — `list_privileges` is a simple,
/// side-effect-free representative of the bundle, and the bundle itself is
/// exactly what `strict_authz` protects (`attome-api/src/system.rs`'s
/// `core_routes`).
async fn admin_privileges_status(app: axum::Router, cookie: &str) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/security/privileges")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.expect("privileges request").status()
}

#[tokio::test]
async fn direct_grant_revoked_via_node_c_is_immediately_rejected_on_nodes_a_and_b() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);
    let node_c = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let subject_id = seed_bare_user(&db, "cross-node-direct-grant-subject").await;
    let grant_id = grant_admin_directly(&db, subject_id).await;
    let subject_cookie = session_cookie_for(subject_id);
    let operator_cookie = seed_admin(&db).await;

    let app_a = full_app(node_a);
    let app_b = full_app(node_b);
    let app_c = full_app(node_c);

    // Populate authorization on nodes A and B.
    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::OK,
        "subject must be recognized as admin on node A before revoke"
    );
    assert_eq!(
        admin_privileges_status(app_b.clone(), &subject_cookie).await,
        StatusCode::OK,
        "subject must be recognized as admin on node B before revoke"
    );

    // Remove the grant through node C.
    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/security/grants/{grant_id}"))
        .header("cookie", &operator_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app_c
        .clone()
        .oneshot(revoke_req)
        .await
        .expect("revoke request via node C");
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "node C's revoke must succeed"
    );

    // Immediately retry through A and B — no sleep, no polling: strict_authz
    // forces resolve_strict on every request to this bundle, so the epoch
    // bump must be visible on the very next request, not eventually.
    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "node A must reject the revoked admin immediately"
    );
    assert_eq!(
        admin_privileges_status(app_b.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "node B must reject the revoked admin immediately"
    );
}

#[tokio::test]
async fn role_removal_via_node_c_is_immediately_rejected_on_nodes_a_and_b() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);
    let node_c = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let subject_id = seed_bare_user(&db, "cross-node-role-subject").await;
    let role_id = grant_admin_via_role(&db, subject_id).await;
    let subject_cookie = session_cookie_for(subject_id);
    let operator_cookie = seed_admin(&db).await;

    let app_a = full_app(node_a);
    let app_b = full_app(node_b);
    let app_c = full_app(node_c);

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::OK,
        "subject must be recognized as admin (via role) on node A before revoke"
    );
    assert_eq!(
        admin_privileges_status(app_b.clone(), &subject_cookie).await,
        StatusCode::OK,
        "subject must be recognized as admin (via role) on node B before revoke"
    );

    // Remove the role through node C.
    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/admin/security/users/{subject_id}/roles/{role_id}"
        ))
        .header("cookie", &operator_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app_c
        .clone()
        .oneshot(revoke_req)
        .await
        .expect("role removal request via node C");
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "node C's role removal must succeed"
    );

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "node A must reject the subject immediately after role removal"
    );
    assert_eq!(
        admin_privileges_status(app_b.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "node B must reject the subject immediately after role removal"
    );
}

#[tokio::test]
async fn team_membership_removal_via_node_c_is_immediately_rejected_on_nodes_a_and_b() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);
    let node_c = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let subject_id = seed_bare_user(&db, "cross-node-team-subject").await;
    let team_id = grant_admin_via_team(&db, subject_id).await;
    let subject_cookie = session_cookie_for(subject_id);
    let operator_cookie = seed_admin(&db).await;

    let app_a = full_app(node_a);
    let app_b = full_app(node_b);
    let app_c = full_app(node_c);

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::OK,
        "subject must be recognized as admin (via team) on node A before revoke"
    );
    assert_eq!(
        admin_privileges_status(app_b.clone(), &subject_cookie).await,
        StatusCode::OK,
        "subject must be recognized as admin (via team) on node B before revoke"
    );

    // Remove the team membership through node C.
    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/admin/security/teams/{team_id}/members/{subject_id}"
        ))
        .header("cookie", &operator_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app_c
        .clone()
        .oneshot(revoke_req)
        .await
        .expect("team membership removal request via node C");
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "node C's team membership removal must succeed"
    );

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "node A must reject the subject immediately after team membership removal"
    );
    assert_eq!(
        admin_privileges_status(app_b.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "node B must reject the subject immediately after team membership removal"
    );
}

/// "Confirm unrelated users are unaffected" at the HTTP level: a second
/// admin, granted and warmed independently, must keep working on node A
/// after the first admin's grant is revoked through node C.
#[tokio::test]
async fn revoking_one_admin_does_not_affect_an_unrelated_admin() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_c = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let subject_id = seed_bare_user(&db, "cross-node-revoked-subject").await;
    let grant_id = grant_admin_directly(&db, subject_id).await;
    let subject_cookie = session_cookie_for(subject_id);

    let unrelated_id = seed_bare_user(&db, "cross-node-unrelated-admin").await;
    grant_admin_directly(&db, unrelated_id).await;
    let unrelated_cookie = session_cookie_for(unrelated_id);

    let operator_cookie = seed_admin(&db).await;

    let app_a = full_app(node_a);
    let app_c = full_app(node_c);

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::OK
    );
    assert_eq!(
        admin_privileges_status(app_a.clone(), &unrelated_cookie).await,
        StatusCode::OK
    );

    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/security/grants/{grant_id}"))
        .header("cookie", &operator_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app_c
        .clone()
        .oneshot(revoke_req)
        .await
        .expect("revoke request via node C");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::FORBIDDEN,
        "the revoked subject must be rejected on node A"
    );
    assert_eq!(
        admin_privileges_status(app_a.clone(), &unrelated_cookie).await,
        StatusCode::OK,
        "an unrelated admin must be unaffected by the other user's revocation"
    );
}

/// "Measure the actual worst-case revocation time" — the end-to-end,
/// HTTP-observable version: from the moment node C's revoke response lands to
/// a subsequent request on node A/B being rejected. Since `strict_authz`
/// forces a fresh `resolve_strict` on every request to this bundle (not an
/// eventual pub/sub-only convergence), this is a single retry, not a polling
/// loop — bounding it here is the same acknowledged-path SLO
/// `invalidate_sync_acknowledged_latency_is_bounded` measures in
/// `attome-security/tests/resolver.rs`, exercised through the real router.
#[tokio::test]
async fn revocation_is_visible_on_other_nodes_within_a_bounded_time() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_c = skip_if_no_db!(test_node().await);
    let db = node_a.state().base.db.clone();

    let subject_id = seed_bare_user(&db, "cross-node-latency-subject").await;
    let grant_id = grant_admin_directly(&db, subject_id).await;
    let subject_cookie = session_cookie_for(subject_id);
    let operator_cookie = seed_admin(&db).await;

    let app_a = full_app(node_a);
    let app_c = full_app(node_c);

    assert_eq!(
        admin_privileges_status(app_a.clone(), &subject_cookie).await,
        StatusCode::OK
    );

    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/security/grants/{grant_id}"))
        .header("cookie", &operator_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app_c
        .clone()
        .oneshot(revoke_req)
        .await
        .expect("revoke request via node C");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let started = std::time::Instant::now();
    let status = admin_privileges_status(app_a.clone(), &subject_cookie).await;
    let elapsed = started.elapsed();

    eprintln!("cross-node revocation visibility latency on node A: {elapsed:?}");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "node A must reject the revoked subject"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "revocation took {elapsed:?} to become visible on node A, exceeding the 2s local-test bound"
    );
}
