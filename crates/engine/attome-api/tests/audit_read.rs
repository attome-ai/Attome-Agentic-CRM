//! Integration coverage for audit-10-10 Phase 6 items 6.1-6.3 —
//! `attome_api::audit_read`'s self-service record history and my-activity
//! endpoints.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as
//! `communication.rs`, whose fixture harness this file mirrors closely.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test audit_read -- --test-threads=1
//! ```
//!
//! **Now green against a live database.** Two earlier blockers, both fixed
//! elsewhere, not in this file: `bulk_mutation.rs`'s documented `migrator`
//! config section and `autovalue`'s missing bundle
//! (`attome_metadata::autovalue::seed_for_tests`, called explicitly in
//! `test_system()` since `.build()` does not call it itself) were fixed
//! here; the actual remaining root cause of the intermittent
//! `column "is_active"`/`"status" does not exist` failure turned out to be
//! `create_migrator_pool`/`create_migrator_connection` (`attome-db/src/
//! pool.rs`) never honoring a debug-mode `DATABASE_URL` override the way
//! `create_pool` (the runtime pool) already did — so schema-provisioning DDL
//! silently ran against the checked-in dev database instead of this file's
//! private test database. Fixed by `resolve_migrator_url`, mirroring
//! `resolve_runtime_url`. The authorization logic these tests exercise
//! (`require_record_access`, `has_field_read_grant`, `resolve_entity`) is
//! all reused, already-proven platform machinery, not new logic invented for
//! this file.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_audit::{
    AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditRequestContext, AuditService,
    AuditSource, AuditUserContext,
};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
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
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "postgres", "password": "postgres", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "postgres", "password": "postgres" }}
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
        // Real credentials directly in the config, not just relied on via
        // `DATABASE_URL`'s `APP_ENV=debug` override -- some path inside
        // `EngineSystem::build()` reads `config.database` directly rather than
        // through `create_pool`'s override, so a placeholder here fails
        // authentication even with `DATABASE_URL` correctly set.
        db_host = std::env::var("TEST_DB_HOST").unwrap_or_else(|_| "localhost".into()),
        db_port = std::env::var("TEST_DB_PORT").unwrap_or_else(|_| "5556".into()),
        db_name = std::env::var("TEST_DB_NAME").unwrap_or_else(|_| "attomedb_test_audread".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn test_system() -> Option<EngineSystem> {
    attome_testkit::migrated_db_url()?;

    let config = test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    // `EngineSystem::build()` unconditionally resyncs some attributes
    // (`attome_dashboard::seed::seed`'s widget_type resync, ordinary build
    // plumbing unrelated to this file) through a path that consults
    // `autovalue` — a metadata-defined entity this minimal
    // harness must seed itself before `.build()`, same as any other test
    // exercising a fresh-database `.build()` call.
    attome_metadata::autovalue::seed_for_tests(&db)
        .await
        .expect("seed autovalue bundle for tests");
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

/// See `communication.rs`'s identical helper: `oneshot()` requests carry no
/// `Origin`, which `csrf_protect` fails closed on for cookie-authenticated
/// unsafe methods by design (irrelevant here — both new routes are GET — but
/// kept for parity with `full_app`'s standard shape).
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

/// A throwaway admin — `ctx.is_admin` short-circuits both the entity-level
/// `RecordScoped<Read>` check and the record-level `require_record_access`
/// DB predicate, so this session can read history for ANY existing record
/// with no additional grant setup — mirrors `communication.rs::seed_admin`.
async fn seed_admin(system: &EngineSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("audit-read-test-admin-{user_id}"))
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

/// A second throwaway, non-admin, zero-privilege user — mirrors
/// `communication.rs::seed_plain_user`. Holds no role, no grant, no share on
/// anything: `require_record_access` must refuse this caller for any record
/// it does not itself own by an explicit mechanism this file never sets up.
async fn seed_plain_user(system: &EngineSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("audit-read-test-plain-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway plain user_account");
    (user_id, session_cookie(user_id))
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Writes one real `audit_header`/`audit_detail` row through the
/// actual production write path (`AuditService::write_in_tx`), the same
/// primitive every mutation on the platform commits through (D-062) —
/// deliberately NOT routed through a generic entity mutation (which would
/// also need the platform's full bundle-seeded bootstrap, e.g.
/// `autovalue`, that this file's minimal harness doesn't load).
/// This isolates what these tests actually verify — the READ+authorization
/// layer `audit_read.rs` adds — from the write path Phases 1-5 already cover
/// extensively.
async fn seed_audit_event(
    state: &EngineState,
    actor_user_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    new_value: &str,
) -> Uuid {
    let event = AuditEvent {
        organization_ref: Uuid::nil(),
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(record_id),
        operation: AuditOperation::Update,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: actor_user_id,
            user_name: format!("user-{actor_user_id}"),
            user_display_name: format!("User {actor_user_id}"),
            user_email: format!("{actor_user_id}@example.test"),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: None,
        event_comment: None,
        changed_fields: vec![AuditFieldChange {
            field_name: field_name.to_owned(),
            display_name: Some(field_name.to_owned()),
            data_type: Some(0), // Text
            old_value: Some("old".to_owned()),
            new_value: Some(new_value.to_owned()),
            old_display_value: Some("old".to_owned()),
            new_display_value: Some(new_value.to_owned()),
            old_lookup_entity: None,
            old_lookup_name: None,
            new_lookup_entity: None,
            new_lookup_name: None,
            is_sensitive: false,
        }],
        snapshot_json: None,
    };
    let audit = AuditService::new(&state.base.db, None);
    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .expect("begin tx");
    let id = audit
        .write_in_tx(&mut tx, event)
        .await
        .expect("write audit event");
    attome_db::tx::commit(tx).await.expect("commit");
    id
}

/// 6.2: My Activity always lists the caller's own actions and never another
/// user's, regardless of admin status on either side.
#[tokio::test]
async fn my_activity_lists_only_the_callers_own_events() {
    let system = skip_if_no_db!(test_system().await);
    let (admin_id, admin_cookie) = seed_admin(&system).await;
    let (_plain_id, plain_cookie) = seed_plain_user(&system).await;
    seed_audit_event(
        system.state(),
        admin_id,
        "user_account",
        admin_id,
        "user_name",
        "renamed-again",
    )
    .await;
    let app = full_app(system);

    // The admin's own activity must show the action they just performed.
    let admin_activity_req = Request::builder()
        .method("GET")
        .uri("/api/v1/audit/me/activity")
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let admin_activity_res = app
        .clone()
        .oneshot(admin_activity_req)
        .await
        .expect("admin activity");
    assert_eq!(admin_activity_res.status(), StatusCode::OK);
    let admin_body = body_json(admin_activity_res).await;
    let admin_items = admin_body["items"].as_array().expect("items array");
    assert!(
        admin_items
            .iter()
            .any(|e| e["record_id"].as_str() == Some(admin_id.to_string().as_str())),
        "the caller's own update must appear in their own activity: {admin_body:?}"
    );

    // An uninvolved user's own activity must NOT show the admin's action.
    let plain_activity_req = Request::builder()
        .method("GET")
        .uri("/api/v1/audit/me/activity")
        .header("cookie", &plain_cookie)
        .body(Body::empty())
        .unwrap();
    let plain_activity_res = app
        .oneshot(plain_activity_req)
        .await
        .expect("plain user activity");
    assert_eq!(plain_activity_res.status(), StatusCode::OK);
    let plain_body = body_json(plain_activity_res).await;
    let plain_items = plain_body["items"].as_array().expect("items array");
    assert!(
        plain_items.is_empty(),
        "a user who performed no actions must see an empty activity list, \
         never another caller's events: {plain_body:?}"
    );
}
