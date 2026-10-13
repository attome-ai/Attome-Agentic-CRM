//! DB-backed proof tests for M01 Core C-06 ("Upsert goes through the
//! primitives"): `POST /api/v1/{entity}/upsert` now resolves the natural key
//! under `FOR UPDATE` and then dispatches to
//! `entity_mutation::create_one`/`update_one` — the same shared primitives
//! interactive create/update use — instead of a hand-rolled
//! `INSERT ... ON CONFLICT`. These tests drive the real route
//! (`attome_records::entity_crud::routes()`) with a real `EngineState`,
//! rather than calling `create_one`/`update_one` directly, because the point
//! is to prove upsert's own dispatch wiring, not just the primitives' own
//! (already independently exercised) behavior.
//!
//! `upsert_record` has no direct-call ("_for") counterpart the way
//! `create_record`/`update_record` do (`create_record_for`/
//! `update_record_for`), so reaching it means going through the real
//! `Authorized<RecordScoped<CreateAndUpdate>>` extractor. Rather than
//! standing up the whole authn/authz middleware stack (`crates/server`'s
//! job), these tests insert the same `AuthorizedContext` extension that
//! middleware would have attached, directly on the request — `AuthorizedContext::new`
//! is `pub` for exactly this reason (`attome_server::authz`'s own doc comment
//! on it).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-records --test upsert -- --test-threads=1
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

use std::collections::{HashMap, HashSet};
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

/// Same shape `attome-ai/tests/record_update_field.rs::test_config` uses —
/// this suite needs the identical infra (Postgres + Redis + storage) a full
/// `EngineState` requires, even though upsert never touches storage itself.
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
// doc comment — `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` from the
// environment synchronously before its first `.await`, and this suite's
// several `#[tokio::test]` functions run concurrently by default.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `attome_audit::seed` (every upsert write audits itself, and that resolves
/// `audit_header` from `entity_info`) plus
/// `attome_metadata::autovalue::seed` (`entity_mutation::create_one` reads auto
/// value rules from `autovalue`). Same two seeds, same reasoning, as
/// `attome-ai/tests/record_update_field.rs::seed_platform`.
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
        .bind(format!("upsert-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Never gated by any privilege check below (`ctx.is_admin` short-circuits
/// both `RecordScoped<CreateAndUpdate>`'s policy and upsert's own
/// `require_admin` index-provisioning gate) — this suite is proving upsert's
/// mutation-primitive dispatch, not its authorization matrix.
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
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    })
}

/// Provisions a throwaway entity with every field this suite's tests need:
/// `email` (the upsert natural key most tests match on), `code` (an
/// autonumber target), `attachment` (a file field, for the file-session
/// rejection test), and `dup_key`/`seq_key` (columns two tests seed with
/// direct SQL before ever going through upsert — one of guidelines §4's four
/// API-first exemptions, "tests against a throwaway database").
///
/// Unique per call (not just per test file) so repeated runs against a
/// persistent throwaway database never collide — same convention
/// `attome-ai`'s `provision_test_entity` uses.
async fn provision_test_entity(state: &EngineState) -> String {
    let logicalname = format!("ups_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "C-06 Upsert Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    for (field, display, field_type) in [
        ("email", "Email", "text"),
        ("code", "Code", "text"),
        ("attachment", "Attachment", "file"),
        ("dup_key", "Dup Key", "text"),
        ("seq_key", "Seq Key", "text"),
    ] {
        attome_metadata::provision::ensure_attribute(
            &state.base.db,
            entity_id,
            field,
            display,
            field_type,
            false,
            false,
            false,
            false,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("provision {field} attribute: {e}"));
    }

    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    logicalname
}

/// Configures an auto value ("autonumber") rule directly against
/// `autovalue` — a metadata-defined entity table with no admin
/// endpoint reused by this suite; direct SQL against a throwaway test
/// database is one of guidelines §4's four API-first exemptions. Every
/// column left out of the INSERT (`id`, `is_active`, `row_version`,
/// `owner_type`, `created_at`) has a DB default (`attome-metadata/src/provision/
/// table.rs::create_table`).
async fn configure_autonumber_rule(db: &attome_db::DbPool, entity_logicalname: &str, field: &str) {
    sqlx::query(
        "INSERT INTO autovalue \
         (entity_logicalname, attribute_logicalname, format, initial_value, next_value, reset_scope) \
         VALUES ($1, $2, 'UP-{SEQ}', 1, 1, 'never')",
    )
    .bind(entity_logicalname)
    .bind(field)
    .execute(db)
    .await
    .expect("insert autovalue rule");
}

fn upsert_request(entity: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{entity}/upsert"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("serialize body"),
        ))
        .expect("build request")
}

/// Sends `req` through the real route, with the same `AuthorizedContext` /
/// `SessionClaims` extensions the production authn/authz middleware would
/// have attached — see this file's module doc comment for why that's the
/// right substitute here rather than standing up that whole stack.
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

async fn change_feed_count(
    db: &attome_db::DbPool,
    entity_logicalname: &str,
    record_id: Uuid,
) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event \
          WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("count change-feed rows")
}

/// C-06 proof bullet 1 ("upsert-insert allocates an autonumber") + bullet 3
/// ("upsert writes exactly one change-feed row"), combined into one test
/// since they're the same insert: before this change, upsert built its own
/// `INSERT ... ON CONFLICT` from `build_insert_binds` and never called
/// `attome_metadata::autovalue::generate_for_create` or
/// `attome_core::change_feed::emit_tx` at all — an autonumber field was
/// left null and no downstream (search/workflow) trigger ever fired for an
/// upserted row.
#[tokio::test]
async fn upsert_insert_allocates_autonumber_and_one_change_feed_row() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;
    configure_autonumber_rule(&state.base.db, &entity, "code").await;

    let email = format!("{}@example.test", Uuid::now_v7());
    let res = send(
        &state,
        user_id,
        upsert_request(&entity, json!({ "match": { "email": email } })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "insert branch must 201");
    let body = body_json(res).await;
    let code = body["data"]["code"]
        .as_str()
        .expect("autovalue must have populated 'code' on insert");
    assert!(
        code.starts_with("UP-"),
        "expected the configured autonumber format, got {code:?}"
    );

    let record_id: Uuid = body["id"].as_str().and_then(|s| s.parse().ok()).unwrap();
    assert_eq!(
        change_feed_count(&state.base.db, &entity, record_id).await,
        1,
        "upsert-insert must write exactly one change-feed row"
    );
}

/// C-06 proof bullet 2 ("upsert with a file key and no session is rejected").
/// Before this change, the file-typed column went straight through
/// `build_insert_binds` like any other field — `lock_file_field_sessions`
/// (the D-14x upload trust anchor) never ran, so a caller could plant an
/// arbitrary object-key string into a file field with no completed upload
/// session backing it.
#[tokio::test]
async fn upsert_insert_with_file_key_and_no_session_is_rejected() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;

    let email = format!("{}@example.test", Uuid::now_v7());
    let res = send(
        &state,
        user_id,
        upsert_request(
            &entity,
            json!({
                "match": { "email": email },
                "data": { "attachment": "not-a-real-upload-session-key" }
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a file key with no backing upload session must be refused"
    );
    let body = body_json(res).await;
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("file fields cannot be set at creation"),
        "expected the file-session trust-anchor rejection, got: {message}"
    );
}

/// Regression for the update branch this change also restructured
/// (`update_one` dispatch, `changed_fields` now diffed against the real
/// `old_row` instead of always `None`): a second upsert on the same match
/// key updates the row already created, rather than duplicating it, and both
/// the create and the update each leave their own change-feed row.
#[tokio::test]
async fn upsert_second_call_updates_existing_record_by_match_key() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;

    let email = format!("{}@example.test", Uuid::now_v7());
    let first = send(
        &state,
        user_id,
        upsert_request(&entity, json!({ "match": { "email": email } })),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = body_json(first).await;
    let record_id: Uuid = first_body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap();
    let row_version = first_body["row_version"].as_i64().unwrap();

    let second = send(
        &state,
        user_id,
        upsert_request(
            &entity,
            json!({
                "match": { "email": email },
                "data": { "code": "manual-override" },
                "row_version": row_version
            }),
        ),
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "conflict branch must update, not 201"
    );
    let second_body = body_json(second).await;
    assert_eq!(
        second_body["id"]
            .as_str()
            .and_then(|s| s.parse::<Uuid>().ok()),
        Some(record_id),
        "must update the same row, not insert a duplicate"
    );
    assert_eq!(
        second_body["data"]["code"].as_str(),
        Some("manual-override")
    );

    assert_eq!(
        change_feed_count(&state.base.db, &entity, record_id).await,
        2,
        "one change-feed row for the insert, one for the update"
    );
}

/// C-06 "Change" bullet: `CREATE UNIQUE INDEX CONCURRENTLY`'s own failure
/// must never reach the caller as raw `sqlx`/Postgres error text. Two active
/// rows sharing the same `dup_key` value make the very first upsert against
/// that key fail to provision its backing unique index (a genuine
/// uniqueness violation in existing data), which is exactly the path that
/// used to echo `"upsert key is not unique in existing data: {e}"` —
/// `{e}`'s `Display` being the raw driver error.
#[tokio::test]
async fn upsert_masks_index_build_failure_instead_of_raw_sql_error() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;

    let table = attome_core::quote_ident(&entity);
    sqlx::query(&format!(
        "INSERT INTO {table} (dup_key) VALUES ('same-value'), ('same-value')"
    ))
    .execute(&state.base.db)
    .await
    .expect("seed two active rows sharing dup_key");

    let res = send(
        &state,
        user_id,
        upsert_request(&entity, json!({ "match": { "dup_key": "same-value" } })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(res).await;
    let message = body["message"].as_str().unwrap_or_default();
    assert_eq!(
        message, "validation error: natural key columns are not indexable",
        "the masked message must replace the raw driver error verbatim"
    );
    assert!(
        !message.to_ascii_lowercase().contains("duplicate key"),
        "must never leak the underlying Postgres error text: {message}"
    );
}

/// C-06 "Change" bullet: a brand-new upsert key must never run its
/// `CREATE UNIQUE INDEX CONCURRENTLY` unbounded on the request thread once
/// the table has grown past the inline size gate (guidelines §9 — same
/// size-gate shape `ATTRIBUTE_INDEX_INLINE_ROW_LIMIT`/
/// `SCHEMA_CHANGE_INLINE_ROW_LIMIT` already apply to their own DDL).
///
/// This does NOT prove the plan's literal "returns 202 with a job id" —
/// there is no durable job wired for this composite, hash-named key shape
/// (`BuildAttributeIndex` only rebuilds a single already-registered
/// attribute's own index), and adding one needs a new `EngineJob` variant
/// plus a worker dispatch arm outside this change's authorized file scope.
/// What this proves instead is the safe containment actually shipped: the
/// request fails closed with a typed, actionable error, and the index is
/// never built, rather than blocking the request for however long a
/// 10,000+ row `CREATE INDEX CONCURRENTLY` takes.
#[tokio::test]
async fn upsert_refuses_new_key_inline_once_table_exceeds_size_gate() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;

    let table = attome_core::quote_ident(&entity);
    sqlx::query(&format!(
        "INSERT INTO {table} (seq_key) SELECT 'row-' || gs FROM generate_series(1, 10001) gs"
    ))
    .execute(&state.base.db)
    .await
    .expect("bulk-seed past the inline row-count gate");

    let indexes_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_indexes WHERE tablename = $1 AND indexname LIKE 'ux_%_upsert_%'",
    )
    .bind(&entity)
    .fetch_one(&state.base.db)
    .await
    .expect("count upsert indexes before");
    assert_eq!(indexes_before, 0);

    let res = send(
        &state,
        user_id,
        upsert_request(
            &entity,
            json!({ "match": { "seq_key": "row-not-present-yet" } }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "must fail closed rather than run the unbounded inline index build"
    );
    let body = body_json(res).await;
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("too large to provision a new upsert key inline"),
        "expected the size-gate refusal, got: {message}"
    );

    let indexes_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_indexes WHERE tablename = $1 AND indexname LIKE 'ux_%_upsert_%'",
    )
    .bind(&entity)
    .fetch_one(&state.base.db)
    .await
    .expect("count upsert indexes after");
    assert_eq!(indexes_after, 0, "the gate must refuse before any DDL runs");
}
