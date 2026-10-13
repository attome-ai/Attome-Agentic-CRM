//! DB-backed proof test for M01 Core C-23 ("Error discrimination at the DB
//! boundary"): a duplicate natural key on `POST /api/v1/{entity}` (the
//! generic entity engine's create path, `entity_mutation::create_one`) must
//! come back as a client-actionable 409 `conflict`, not a masked 500
//! `internal_error` — the exact failure mode the plan's audit found at 1,522
//! call sites that followed a DB call directly with a blanket
//! `AppError::internal(e)`.
//!
//! The generic entity engine has no per-attribute "unique" flag of its own
//! (`attome_metadata::provision::ensure_attribute` takes no such parameter) — the
//! real product path that puts a genuine `UNIQUE` constraint on an entity
//! column today is upsert's own dynamically-provisioned `ux_%_upsert_%`
//! index (see `tests/upsert.rs`). Rather than reaching for that route (which
//! would be testing upsert's dispatch again, not create's own DB-error
//! classification), this test provisions the unique index directly with SQL
//! — one of guidelines §4's four API-first exemptions, "tests against a
//! throwaway database" — so the second `create_record` INSERT hits a real
//! PostgreSQL SQLSTATE `23505`, and `entity_mutation::classify_db_error`
//! (which now falls through to `attome_db::classify` for everything except its
//! own already-handled 23505 branch) is exercised end to end through the
//! real HTTP route, not by calling the classifier directly.
//!
//! Same harness shape as `tests/upsert.rs` next door (D-343: one throwaway
//! database per test binary).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-records --test create_duplicate_key -- --test-threads=1
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

use std::collections::HashSet;
use std::sync::Arc;

use attome_auth::{SessionClaims, TokenType};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_server::authz::AuthorizedContext;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

/// Same shape `tests/upsert.rs::test_config` uses.
fn test_config(direct_url: &str) -> AppConfig {
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
                "connection_number": 5, "timeout": 5.0,
                "direct_url": "{direct_url}"
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
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
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
        direct_url = direct_url,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

// SAFETY: see `attome-ai/tests/record_update_field.rs`'s identical `ENV_LOCK`
// doc comment.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `attome_audit::seed` (every create writes an audit event, which resolves
/// `audit_header` from `entity_info`) plus `attome_metadata::autovalue::seed`
/// (`entity_mutation::create_one` reads auto value rules unconditionally).
async fn seed_platform(db: &attome_db::DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            attome_audit::seed(db)
                .await
                .expect("seed audit entity metadata");
            attome_metadata::autovalue::seed_for_tests(db)
                .await
                .expect("seed autovalue entity + table");
        })
        .await;
}

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url);
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
    seed_platform(&db).await;
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

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("create-dup-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Never gated by any privilege check below (`ctx.is_admin` short-circuits
/// `RecordScoped<Create>`'s policy) — this suite proves create's own DB-error
/// classification, not its authorization matrix.
fn security_context(user_id: Uuid) -> Arc<SecurityContext> {
    Arc::new(SecurityContext {
        user_id,
        is_admin: true,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: std::collections::HashMap::new(),
        role_ids: None,
        service_principal: false,
    })
}

/// Provisions a throwaway entity with one plain text field (`email`), then
/// puts a genuine `UNIQUE` index directly on it — one of guidelines §4's
/// four API-first exemptions ("tests against a throwaway database"). This
/// stands in for a real per-field unique constraint until the generic entity
/// engine grows one of its own; what this test actually proves is
/// `entity_mutation::create_one`'s reaction to a real SQLSTATE 23505 off its
/// own plain INSERT, which is identical either way the constraint got there.
async fn provision_test_entity(state: &EngineState) -> String {
    let logicalname = format!("cdk_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "C-23 Create-Duplicate-Key Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "email",
        "Email",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision email attribute");

    let table = attome_core::quote_ident(&logicalname);
    sqlx::query(&format!(
        "CREATE UNIQUE INDEX ON {table} (email) WHERE is_active IS NULL OR is_active = true"
    ))
    .execute(&state.base.db)
    .await
    .expect("provision a genuine unique index on the natural key column");

    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    logicalname
}

fn create_request(entity: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{entity}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("serialize body"),
        ))
        .expect("build request")
}

/// Same substitute for the real authn/authz middleware stack `tests/upsert.rs`
/// documents on its own identical helper.
async fn send(
    state: &EngineState,
    user_id: Uuid,
    mut req: Request<Body>,
) -> axum::response::Response {
    req.extensions_mut()
        .insert(AuthorizedContext::new(security_context(user_id)));
    req.extensions_mut().insert(SessionClaims {
        sub: user_id,
        iat: 0,
        exp: i64::MAX,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: "attome-test".into(),
        aud: "attome-test".into(),
        typ: TokenType::Session,
    });
    attome_records::entity_crud::routes()
        .with_state(state.clone())
        .oneshot(req)
        .await
        .expect("router call")
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("parse response body as JSON")
}

/// C-23's own DB proof bullet: "duplicate natural key on create returns 409
/// with `error: "conflict"`".
#[tokio::test]
async fn create_with_duplicate_natural_key_returns_409_conflict() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;

    let email = format!("{}@example.test", Uuid::now_v7());

    let first = send(
        &state,
        user_id,
        create_request(&entity, json!({ "email": email })),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED, "first create must 201");

    let second = send(
        &state,
        user_id,
        create_request(&entity, json!({ "email": email })),
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "a duplicate natural key on create must be a 409, not a masked 500"
    );
    let body = body_json(second).await;
    assert_eq!(
        body["error"], "conflict",
        "expected the stable `conflict` error code, got: {body}"
    );
    assert!(
        !body["message"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("duplicate key"),
        "must never leak the raw driver error text: {body}"
    );
}
