//! M01 Core P3 gap (D-455) — regression coverage for the generic M:M
//! relationship mechanism: `relationship_info` admin CRUD
//! (`relationship_admin.rs`) and the record-level
//! `/api/v1/{entity}/{id}/related/{relationship}` GET/POST/DELETE API
//! (`entity_crud/related.rs`).
//!
//! Covers:
//! - admin `POST /api/v1/admin/relationships` provisions the join table and
//!   the relationship becomes immediately usable (registry pre-warm/reload,
//!   not the pub/sub doorbell — same "no artificial `sleep`" posture other
//!   suites in this file take; `metadata_registry_enabled: false` below
//!   removes the `EntityMetaRegistry` race note `entity_round_trip.rs`
//!   documents, but the relationship registry's own reload here is
//!   synchronous inside the admin handler regardless);
//! - POST link is upsert-by-natural-key: linking an already-linked pair is
//!   a no-op 204, and linking again after an unlink reactivates the same
//!   join row rather than erroring;
//! - GET list only ever returns a live join row whose OTHER endpoint is
//!   also `is_active` — soft-deleting either side hides the link, verified
//!   from both directions;
//! - link/unlink require `update` privilege on BOTH sides: no privilege on
//!   the anchor entity is a 403 (the `RecordScoped<Update>` extractor,
//!   before the handler runs); privilege on the anchor only, none on the
//!   other side, is a 404 (this file's own `require_other_side_access`,
//!   matching `require_referenced_record_access`'s not-found-not-forbidden
//!   convention); privilege on both succeeds.
//! - C-09 (M01 §7): link/unlink are real mutations — an audit header, a
//!   change-feed row per endpoint entity, and a sticky-primary pin, for
//!   both directions.
//! - C-21 (M01 §7): a relationship retired then recreated under the same
//!   `name` with SWAPPED endpoints is refused (`409`) rather than silently
//!   reusing the stale physical join table the retirement left behind.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `entity_round_trip.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test relationship_related -- --test-threads=1
//! ```

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
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use fred::interfaces::KeysInterface;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (copied near-verbatim from entity_round_trip.rs / state_lifecycle.rs) ──

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

async fn build_test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
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

/// The system and router every test in this binary shares (build-loop plan,
/// Phase 3 task 4). Building a fresh `EngineSystem` per test cost ~0.3 s each;
/// the tests already share this binary's database, and each one provisions
/// its own uniquely named entities, users and roles, so sharing the in-memory
/// system adds no coupling the database did not already have. Tests run on
/// `attome_testkit::shared_runtime`, which keeps the pools' connections alive
/// between tests.
#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn state(&self) -> &EngineState {
        &self.state
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            Some(TestSystem {
                state,
                app: build_app(system),
            })
        })
        .await
        .clone()
}

fn full_app(system: TestSystem) -> axum::Router {
    system.app
}

fn build_app(system: EngineSystem) -> axum::Router {
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

async fn seed_admin(system: &TestSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("relationship-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded by attome_security::seed");

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

    session_cookie(user_id)
}

/// Same seed as `seed_admin`, but also returns the admin's own user id —
/// needed only by the C-09 coverage below, to read
/// `pin_write_with_current_lsn`'s Redis key (`attome-db:rw-pin:{user_id}`)
/// directly, same technique `rw_pin.rs`'s suite already uses against the
/// ordinary generic-CRUD create/update/delete call sites.
async fn seed_admin_with_id(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("relationship-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded by attome_security::seed");

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

/// Same key-shape literal `rw_pin.rs`'s own suite hard-codes
/// (`sticky_primary::key()` is private to `attome-cache`) —
/// `"attome-db:rw-pin:{user_id}"`, guidelines §5's `{crate}:{purpose}:{id}`
/// convention.
fn rw_pin_key(user_id: Uuid) -> String {
    format!("attome-db:rw-pin:{user_id}")
}

async fn seed_non_admin_user(db: &attome_db::DbPool, tag: &str) -> (Uuid, String, String) {
    let user_id = Uuid::now_v7();
    let email = format!("relationship-test-{tag}-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("relationship-test-{tag}-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway non-admin user_account");
    (user_id, email, session_cookie(user_id))
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = to_bytes(res.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn req(method: &str, uri: &str, cookie: &str, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

/// Provisions one entity with a single `title` (text) field, via the admin
/// API — same shape `entity_round_trip.rs::provision_test_entity` uses,
/// minus the shared-app return (this suite needs two entities under one
/// app, so the app is built once by the caller).
async fn provision_entity(app: &axum::Router, admin_cookie: &str, prefix: &str) -> String {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({"logicalname": logicalname, "name": prefix})),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity {prefix}");
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            Some(&json!({"logicalname": "title", "name": "Title", "field_type": "text"})),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create title field on {prefix}"
    );

    logicalname
}

async fn create_record(app: &axum::Router, cookie: &str, entity: &str, title: &str) -> Uuid {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}"),
            cookie,
            Some(&json!({"title": title})),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create record on {entity}"
    );
    let record = body_json(res).await;
    Uuid::parse_str(record["id"].as_str().expect("record id")).expect("record id parses")
}

async fn grant(app: &axum::Router, admin_cookie: &str, user_email: &str, privilege_key: &str) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/security/grants",
            admin_cookie,
            Some(&json!({"user_email": user_email, "privilege_key": privilege_key})),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "grant {privilege_key} to {user_email}"
    );
}

/// Creates a relationship via the admin API. Returns its `name`.
async fn create_relationship(
    app: &axum::Router,
    admin_cookie: &str,
    entity_a: &str,
    entity_b: &str,
) -> String {
    let name = format!("rel_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/relationships",
            admin_cookie,
            Some(&json!({
                "name": name,
                "entity_a": entity_a,
                "entity_b": entity_b,
                "role_a": "As",
                "role_b": "Bs",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create relationship");
    let body = body_json(res).await;
    assert_eq!(body["entity_a"], entity_a);
    assert_eq!(body["entity_b"], entity_b);
    assert_eq!(body["cascade"], "orphan", "default cascade policy");
    name
}

async fn related_ids(
    app: &axum::Router,
    cookie: &str,
    entity: &str,
    id: Uuid,
    rel: &str,
) -> Vec<Uuid> {
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{entity}/{id}/related/{rel}"),
            cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "list related");
    let body = body_json(res).await;
    body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|it| Uuid::parse_str(it["id"].as_str().expect("item id")).expect("item id parses"))
        .collect()
}

#[test]
fn link_unlink_is_upsert_by_natural_key() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let entity_a = provision_entity(&app, &admin_cookie, "rel_a").await;
        let entity_b = provision_entity(&app, &admin_cookie, "rel_b").await;
        let rel = create_relationship(&app, &admin_cookie, &entity_a, &entity_b).await;

        let a_id = create_record(&app, &admin_cookie, &entity_a, "a1").await;
        let b_id = create_record(&app, &admin_cookie, &entity_b, "b1").await;

        // Not linked yet.
        assert!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel)
                .await
                .is_empty()
        );

        // Link.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &admin_cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "first link");
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id]
        );

        // Linking the same pair again is a no-op, not a conflict — upsert by
        // natural key (a_id, b_id), the checklist's explicit requirement.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &admin_cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NO_CONTENT,
            "duplicate link is idempotent"
        );
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id]
        );

        // Unlink.
        let res = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}?id={b_id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "unlink");
        assert!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel)
                .await
                .is_empty()
        );

        // Unlinking an already-unlinked pair is a 404 (nothing live matched).
        let res = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}?id={b_id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "double unlink");

        // Re-linking after an unlink reactivates the same join row (upsert),
        // not a distinct new one.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &admin_cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "re-link after unlink");
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id]
        );
    })
}

#[test]
fn soft_deleting_either_side_hides_the_link() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let entity_a = provision_entity(&app, &admin_cookie, "rel_a").await;
        let entity_b = provision_entity(&app, &admin_cookie, "rel_b").await;
        let rel = create_relationship(&app, &admin_cookie, &entity_a, &entity_b).await;

        let a_id = create_record(&app, &admin_cookie, &entity_a, "a1").await;
        let b_id = create_record(&app, &admin_cookie, &entity_b, "b1").await;

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &admin_cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id]
        );

        // Soft-delete B's record (ordinary generic-CRUD DELETE — no If-Match
        // required on delete, same as entity_round_trip.rs's
        // if_match_is_optional_on_delete_and_restore).
        let res = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v1/{entity_b}/{b_id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "soft-delete b1");

        // The link is now hidden from A's side, even though the join row itself
        // was never touched (cascade policy defaults to "orphan" — metadata
        // only in this phase, see RelationshipCascade's doc comment).
        assert!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel)
                .await
                .is_empty(),
            "a soft-deleted b1 must not appear in a1's related list"
        );

        // Restoring b1 makes the link visible again — proves the join row
        // itself was left alone, only the read-side filter hid it.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_b}/{b_id}/restore"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "restore b1");
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id]
        );
    })
}

#[test]
fn link_requires_update_privilege_on_both_sides() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let entity_a = provision_entity(&app, &admin_cookie, "rel_a").await;
        let entity_b = provision_entity(&app, &admin_cookie, "rel_b").await;
        let rel = create_relationship(&app, &admin_cookie, &entity_a, &entity_b).await;

        let a_id = create_record(&app, &admin_cookie, &entity_a, "a1").await;
        let b_id = create_record(&app, &admin_cookie, &entity_b, "b1").await;

        let (_, email, cookie) = seed_non_admin_user(&db, "linker").await;

        // No privilege on either side: the RecordScoped<Update> extractor
        // rejects before the handler runs — 403.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "no privilege on either side"
        );

        // Privilege on the anchor (A) only: the extractor now passes, but
        // require_other_side_access's entity-level ctx.require on B fails,
        // mapped to NotFound (never leaks whether the B record exists to a
        // caller who cannot act on entity B at all).
        grant(&app, &admin_cookie, &email, &format!("{entity_a}.update")).await;
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "privilege on A only must not be enough to link into B"
        );
        assert!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel)
                .await
                .is_empty(),
            "the rejected link attempt must not have written anything"
        );

        // Privilege on both sides: link succeeds.
        grant(&app, &admin_cookie, &email, &format!("{entity_b}.update")).await;
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NO_CONTENT,
            "privilege on both sides links successfully"
        );
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id]
        );

        // Same two-sided requirement applies to unlink.
        let res = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}?id={b_id}"),
                &cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NO_CONTENT,
            "unlink with privilege on both sides"
        );
    })
}

/// C-09 (M01 §7) — "Related link/unlink are real mutations": before this,
/// `link_related`/`unlink_related` wrote only the join row itself, with no
/// audit event, no change-feed row, and no sticky-primary pin. Proves all
/// three now fire, for both directions:
/// - exactly one `audit_header` row per call, category=Relationship
///   (4), keyed to the anchor record, `Create` for link / `SoftDelete` for
///   unlink (see `related.rs`'s doc comment on why those two are reused
///   rather than a dedicated `Link`/`Unlink` operation);
/// - exactly two `entity_change_event` rows per call (`operation =
///   'update'`), one per endpoint entity — not one, and not zero;
/// - a sticky-primary pin lands after both, and `list_related` immediately
///   after `link` (against the very same pool it always reads from in this
///   harness) already sees the row — the concrete symptom the checklist
///   named (`list_related` right after `link` missing the row on a real
///   lagging replica).
#[test]
fn link_and_unlink_write_audit_change_feed_and_pin_the_writer() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, admin_cookie) = seed_admin_with_id(&system).await;
        let db = system.state().base.db.clone();
        let redis = system.state().base.redis.clone();
        let app = full_app(system);

        let entity_a = provision_entity(&app, &admin_cookie, "rel_a").await;
        let entity_b = provision_entity(&app, &admin_cookie, "rel_b").await;
        let rel = create_relationship(&app, &admin_cookie, &entity_a, &entity_b).await;

        let a_id = create_record(&app, &admin_cookie, &entity_a, "a1").await;
        let b_id = create_record(&app, &admin_cookie, &entity_b, "b1").await;

        // `create_record` above is itself a write by this same admin, so it
        // legitimately leaves a sticky-primary pin behind. Clear it so the
        // pin assertion after `link` below proves `link` itself established
        // the pin, not leftover state from setup — same fix
        // `rw_pin.rs::http_create_pins_the_writer_to_a_real_postgres_lsn`
        // applies for the identical reason.
        let _: () = redis
            .del(rw_pin_key(user_id))
            .await
            .expect("clearing the setup pin must not error");
        assert_eq!(
            check_pin(&redis, user_id).await,
            PinCheck::None,
            "sanity: no pin before the link under test"
        );

        // ── Link ──
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}"),
                &admin_cookie,
                Some(&json!({"id": b_id})),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "link");

        // The read-after-write proof itself: no artificial wait, straight to
        // `list_related` on the same pool this harness always uses.
        assert_eq!(
            related_ids(&app, &admin_cookie, &entity_a, a_id, &rel).await,
            vec![b_id],
            "list_related must see the link immediately after it commits"
        );

        let link_headers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_header \
         WHERE category = 4 AND record_id = $1 AND operation = 0",
        )
        .bind(a_id)
        .fetch_one(&db)
        .await
        .expect("count Relationship/Create audit headers after link");
        assert_eq!(
            link_headers, 1,
            "link must write exactly one Relationship-category audit header"
        );

        let link_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM entity_change_event \
         WHERE operation = 'update' AND record_id IN ($1, $2)",
        )
        .bind(a_id)
        .bind(b_id)
        .fetch_one(&db)
        .await
        .expect("count change-feed rows after link");
        assert_eq!(
            link_events, 2,
            "link must emit one change-feed row for EACH endpoint entity"
        );
        let link_event_entities: Vec<String> = sqlx::query_scalar(
            "SELECT entity_logicalname FROM entity_change_event \
         WHERE operation = 'update' AND record_id IN ($1, $2) ORDER BY entity_logicalname",
        )
        .bind(a_id)
        .bind(b_id)
        .fetch_all(&db)
        .await
        .expect("fetch change-feed entity names after link");
        let mut expected_entities = vec![entity_a.clone(), entity_b.clone()];
        expected_entities.sort();
        assert_eq!(
            link_event_entities, expected_entities,
            "the two change-feed rows must be one for each endpoint entity, not both for one"
        );

        match check_pin(&redis, user_id).await {
            PinCheck::Pinned(lsn) => assert!(
                parse_lsn(&lsn).is_some(),
                "pinned value {lsn:?} must look like a real pg_lsn (\"XXXX/YYYYYYYY\")"
            ),
            other => panic!("expected a sticky-primary pin after link, got {other:?}"),
        }

        // ── Unlink ──
        let _: () = redis
            .del(rw_pin_key(user_id))
            .await
            .expect("clearing the link pin must not error");

        let res = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v1/{entity_a}/{a_id}/related/{rel}?id={b_id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "unlink");

        let unlink_headers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_header \
         WHERE category = 4 AND record_id = $1 AND operation = 2",
        )
        .bind(a_id)
        .fetch_one(&db)
        .await
        .expect("count Relationship/SoftDelete audit headers after unlink");
        assert_eq!(
            unlink_headers, 1,
            "unlink must write exactly one Relationship-category audit header"
        );

        // Link already wrote 2 (`operation = 'update'`) rows for these two
        // record ids above; unlink must add exactly 2 more, for a running total
        // of 4 — not silently reuse link's rows, and not skip a side.
        let total_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM entity_change_event \
         WHERE operation = 'update' AND record_id IN ($1, $2)",
        )
        .bind(a_id)
        .bind(b_id)
        .fetch_one(&db)
        .await
        .expect("count change-feed rows after unlink");
        assert_eq!(
            total_events, 4,
            "unlink must ALSO emit one change-feed row for each endpoint entity"
        );

        match check_pin(&redis, user_id).await {
            PinCheck::Pinned(lsn) => assert!(
                parse_lsn(&lsn).is_some(),
                "pinned value {lsn:?} must look like a real pg_lsn after unlink too"
            ),
            other => panic!("expected a sticky-primary pin after unlink, got {other:?}"),
        }
    })
}

/// C-21 (M01 §7) — a relationship retired then recreated under the same
/// `name` but with `entity_a`/`entity_b` SWAPPED must not silently reuse the
/// stale physical join table the retirement left behind: `retire_relationship`
/// (the admin `DELETE`) only soft-deletes the `relationship_info`
/// row, it never drops `mm_{name}` or its data
/// (`attome_metadata::provision::relationship::retire_relationship`'s doc
/// comment), and `relationship_info`'s uniqueness on `name` is
/// partial (`WHERE NOT is_deleted`) — so the recreate below hits
/// `reconcile_relationship`'s `existing = None` branch exactly like a
/// brand-new relationship would. Before this fix, `CREATE TABLE IF NOT
/// EXISTS` alone would have no-op'd onto the OLD table, whose FKs still
/// point at the original (now swapped-away-from) endpoints. Expects `409`.
#[test]
fn recreating_a_retired_relationship_with_swapped_endpoints_is_a_conflict() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let entity_x = provision_entity(&app, &admin_cookie, "relswapx").await;
        let entity_y = provision_entity(&app, &admin_cookie, "relswapy").await;
        let name = format!("relswap_{}", Uuid::now_v7().simple());

        // Create X -> Y, which provisions mm_{name} with a_id -> X, b_id -> Y.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/relationships",
                &admin_cookie,
                Some(&json!({
                    "name": name,
                    "entity_a": entity_x,
                    "entity_b": entity_y,
                    "role_a": "Xs",
                    "role_b": "Ys",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "create the original X -> Y relationship"
        );
        let created = body_json(res).await;
        let id = created["id"].as_str().expect("relationship id").to_owned();

        // Retire it — the definition row goes away, mm_{name} and its rows
        // do not.
        let res = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v1/admin/relationships/{id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NO_CONTENT,
            "retire the original relationship"
        );

        // Recreate under the SAME name with entity_a/entity_b SWAPPED
        // (Y -> X instead of X -> Y). The stale mm_{name} table's FKs still
        // point at X/Y in the ORIGINAL order, so this must be refused.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/relationships",
                &admin_cookie,
                Some(&json!({
                    "name": name,
                    "entity_a": entity_y,
                    "entity_b": entity_x,
                    "role_a": "Ys",
                    "role_b": "Xs",
                })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let body = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "recreate with swapped endpoints must refuse to reuse the stale join \
         table, got {status} with body {body:?}"
        );

        // Sanity check the OTHER direction: reusing the same retired name with
        // its ORIGINAL (unswapped) endpoints must still succeed — this is the
        // ordinary, already-supported retire/recreate path, not something C-21
        // should have broken.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/relationships",
                &admin_cookie,
                Some(&json!({
                    "name": name,
                    "entity_a": entity_x,
                    "entity_b": entity_y,
                    "role_a": "Xs2",
                    "role_b": "Ys2",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "recreating with the ORIGINAL endpoints must still succeed"
        );
    })
}
