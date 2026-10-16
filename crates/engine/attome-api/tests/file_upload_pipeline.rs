//! Integration test for P-file-upload-pipeline: upload session lifecycle,
//! finalize verification, the async scan job, and the entity-mutation
//! write-path gate that refuses any file-field value not backed by a
//! completed, owned, clean session.
//!
//! Requires a live Postgres (`DATABASE_URL`), Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`), and a reachable RustFS/MinIO/S3
//! bucket (`S3_ACCESS_KEY`/`S3_SECRET_KEY` env, `TEST_S3_BUCKET` optional,
//! defaults to `attomebase`) — this suite does real PUT/GET against object
//! storage, unlike the other attome-api suites, which never touch a real
//! bucket. The "client PUT" step uses `object_store` directly against the
//! key parsed out of the presigned URL (rather than a separate HTTP client
//! crate), so this suite does NOT prove a client can use a presigned URL —
//! `attome-storage/tests/presign_roundtrip.rs` does, with real HTTP PUT/GET
//! against the exact URLs. What this suite proves is the
//! session/finalize/scan/write-path-gate logic layered on top. No `clamd`
//! is required: these tests only exercise the parts of the pipeline that
//! don't depend on a malware scanner being reachable (session create/
//! finalize, the size-mismatch reject path, and the write-path gate) — the
//! malware-positive and clean-promotion paths are NOT exercised here; see
//! `crates/engine/attome-api/src/files_scan.rs`'s own doc comments for what a
//! `clamd`-backed follow-up pass still owes.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! $env:S3_ACCESS_KEY = "..."; $env:S3_SECRET_KEY = "..."
//! cargo test -p attome-api --test file_upload_pipeline -- --test-threads=1
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
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use object_store::ObjectStoreExt;
use object_store::path::Path as ObjectPath;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use uuid::Uuid;

/// Extracts the object key from a path-style presigned URL
/// (`http://host:port/{bucket}/{key...}?query`) — this suite's stand-in for
/// a real client, since it drives the upload with `object_store` directly
/// rather than a separate HTTP client (see the file's own header comment).
fn object_key_from_presigned_url(url: &str, bucket: &str) -> String {
    let after_scheme = url.split("://").nth(1).expect("URL must have a scheme");
    let (_, path) = after_scheme.split_once('/').expect("URL must have a path");
    let path = path
        .split('?')
        .next()
        .expect("split always yields at least one item");
    path.strip_prefix(&format!("{bucket}/"))
        .unwrap_or(path)
        .to_string()
}

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn s3_bucket() -> String {
    std::env::var("TEST_S3_BUCKET").unwrap_or_else(|_| "attomebase".into())
}

/// `audit.chainer_enabled` is pinned false (D-316 made true the code
/// default): this suite asserts `audit_header` rows exist immediately
/// after the mutation that produced them, which is the synchronous path's
/// guarantee. On the cutover path those rows only appear once the separate
/// `audit_chainer` process drains `audit_ingest`, and nothing starts it
/// here.
fn test_config() -> AppConfig {
    let access_key = attome_testkit::s3_env("S3_ACCESS_KEY");
    let secret_key = attome_testkit::s3_env("S3_SECRET_KEY");

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
                "metadata_registry_enabled": true
            }},
            "storage": {{
                "s3_endpoint": "http://127.0.0.1:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "{access_key}", "s3_secret_key": "{secret_key}",
                "s3_bucket": "{bucket}", "s3_use_path_style": true, "s3_verify_ssl": false,
                "max_upload_size_bytes": 1024
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
            "cors": {{ "allowed_origins": ["http://test.local"] }},
            "audit": {{ "chainer_enabled": false }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        access_key = access_key,
        secret_key = secret_key,
        bucket = s3_bucket(),
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_system() -> Option<EngineSystem> {
    test_system_with_config(test_config()).await
}

/// Same wiring as `test_system()`, but lets a caller start from a mutated
/// `test_config()` — e.g. the storage-quota tests below, which each need
/// their own `max_user_storage_bytes`/`max_deployment_storage_bytes` and
/// would otherwise have to share one value across every test in this file.
async fn test_system_with_config(config: AppConfig) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    attome_testkit::migrated_db_url()?;
    attome_testkit::s3_or_skip()?;

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

async fn seed_admin(system: &EngineSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("file-pipeline-test-admin-{user_id}"))
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

/// `files.rs`'s `resolve_file_field` only ever reads the arc-swap metadata
/// registry (unlike `entity_crud.rs::resolve_entity`, it has no pre-Plan-1.2
/// direct-Postgres fallback — see that function's own doc comment). The
/// registry only rebuilds ~250ms after provisioning's `meta_version` pub/sub
/// signal (same race `tests/metadata_cache.rs` bounds), so the first
/// files.rs request right after provisioning an entity/field is expected to
/// 404 briefly. Poll bounded, same pattern as that suite.
async fn create_upload_session_with_retry(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
    body: &str,
) -> axum::response::Response {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session"
            ))
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        if res.status() != StatusCode::NOT_FOUND || tokio::time::Instant::now() >= deadline {
            return res;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Provisions an entity with one `file`-typed field, then creates one record
/// on it. Returns (logicalname, record_id, row_version).
async fn provision_entity_with_file_field(
    app: &axum::Router,
    admin_cookie: &str,
) -> (String, String, i64) {
    let logicalname = format!("file_pipeline_{}", Uuid::now_v7().simple());

    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"File Pipeline Test"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(create_entity_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    let create_field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"attachment","name":"Attachment","field_type":"file"}"#,
        ))
        .unwrap();
    let res = app.clone().oneshot(create_field_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create file field");

    let create_text_field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        ))
        .unwrap();
    let res = app.clone().oneshot(create_text_field_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create title field");

    // A file-typed field cannot be set on create (no session can possibly
    // exist yet for a record with no id) — the record is created with an
    // unrelated field, then a session is created against its now-real id.
    // Registry rebuild race (see create_upload_session_with_retry's doc
    // comment) applies here too, since metadata_registry_enabled = true.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let res = loop {
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"test record"}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.unwrap();
        if res.status() != StatusCode::NOT_FOUND || tokio::time::Instant::now() >= deadline {
            break res;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let record_id = created["id"].as_str().unwrap().to_owned();
    let row_version = created["row_version"].as_i64().unwrap();

    (logicalname, record_id, row_version)
}

#[tokio::test]
async fn create_finalize_and_patch_gate_round_trip() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let storage = system.state().base.storage.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    // ── Create upload session ───────────────────────────────────────────
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"hello.txt","content_type":"text/plain","declared_size_bytes":11}"#,
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = session["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned();
    let upload_url = session["upload_url"]
        .as_str()
        .expect("upload_url")
        .to_owned();

    // ── Simulate the client PUT (real RustFS) ───────────────────────────
    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    storage
        .store()
        .put(&path, "hello world".into())
        .await
        .expect("put via object_store");

    // ── Finalize ─────────────────────────────────────────────────────────
    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");
    assert_eq!(finalized["status"], "uploaded");

    // ── PATCH with the raw (not-yet-clean) key must 422 ─────────────────
    // The write-path gate (entity_mutation::lock_file_field_sessions) only
    // accepts a `status = 'clean'` session — finalize alone (`uploaded`)
    // must never be sufficient, since the malware scan hasn't run yet.
    let patch_before_scan_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", "\"0\"")
        .body(Body::from(format!(
            r#"{{"attachment":"{logicalname}/{record_id}/attachment/{session_id}-hello.txt"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(patch_before_scan_req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "an unscanned (not yet clean) session must not be PATCH-accepted"
    );
}

#[tokio::test]
async fn finalize_rejects_and_deletes_an_oversized_upload() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let storage = system.state().base.storage.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"small.txt","content_type":"text/plain","declared_size_bytes":5}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let session = body_json(res).await;
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    // Uploads more bytes than declared (5) — finalize must reject this.
    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    storage
        .store()
        .put(&path, "this is way more than five bytes".into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");
    assert_eq!(finalized["status"], "rejected");

    // The quarantine object must actually be gone (no forensic value in a
    // simple size mismatch, unlike a malware-positive result).
    let object_key =
        format!("_quarantine/{logicalname}/{record_id}/attachment/{session_id}-small.txt");
    let path = object_store::path::Path::parse(&object_key).unwrap();
    use object_store::ObjectStoreExt;
    let head_result = storage.store().head(&path).await;
    assert!(
        head_result.is_err(),
        "rejected quarantine object should have been deleted"
    );
}

#[tokio::test]
async fn patch_rejects_a_key_with_no_upload_session_at_all() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", "\"0\"")
        .body(Body::from(format!(
            r#"{{"attachment":"{logicalname}/{record_id}/attachment/{}-nosession.txt"}}"#,
            Uuid::now_v7()
        )))
        .unwrap();
    let res = app.clone().oneshot(patch_req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a file key with no backing upload session at all must 422"
    );
}

/// BST-0d/D-617: a generic `file` field's session create refuses a declared
/// type outside the platform allowlist, before any session row or presigned
/// URL exists. Replaces `create_accepts_any_content_type`, which pinned the
/// allowlist *removal* (and asserted `201 CREATED` on a route that answers
/// `200 OK`). The three types here are the plan's own never-allow list: every
/// one of them is markup a browser executes when a download is served inline,
/// which is exactly what BST-F12/BST-F2 were about.
#[tokio::test]
async fn an_html_upload_session_is_refused() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    for content_type in ["text/html", "image/svg+xml", "application/xhtml+xml"] {
        let res = create_upload_session_with_retry(
            &app,
            &admin_cookie,
            &logicalname,
            &record_id,
            &format!(
                r#"{{"filename":"code.html","content_type":"{content_type}","declared_size_bytes":11}}"#
            ),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{content_type} must never be an allowed generic file upload type"
        );
    }
}

/// The positive twin of BST-0d: a declared type that *is* on the allowlist
/// still creates a session, so the refusal above is a policy and not an
/// accidental blanket rejection.
#[tokio::test]
async fn an_allowlisted_upload_session_is_accepted() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"report.pdf","content_type":"application/pdf","declared_size_bytes":11}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_rejects_a_declared_size_over_the_configured_maximum() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    // test_config sets storage.max_upload_size_bytes = 1024.
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"big.txt","content_type":"text/plain","declared_size_bytes":999999999}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// Item 26 remediation: `storage.max_user_storage_bytes` bounds one user's
/// running total (in-flight + clean), independent of
/// `max_upload_size_bytes`'s per-request ceiling — a 50-byte request that
/// would pass that per-request check on its own must still be rejected once
/// it would push the user's own total over their 10-byte quota.
#[tokio::test]
async fn create_rejects_when_it_would_exceed_the_per_user_storage_quota() {
    let mut config = test_config();
    config.storage.max_user_storage_bytes = Some(10);
    let system = skip_if_no_db!(test_system_with_config(config).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"a.txt","content_type":"text/plain","declared_size_bytes":50}"#,
    )
    .await;
    // Z6-T7: 413 naming the quota.
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Same remediation, the deployment-wide half: `max_deployment_storage_bytes`
/// caps the whole deployment's promoted (`clean`) storage regardless of which
/// user is asking — set low enough here that it must reject independent of
/// whatever `clean` bytes earlier tests in this shared throwaway database may
/// have already left behind.
#[tokio::test]
async fn create_rejects_when_it_would_exceed_the_deployment_storage_quota() {
    let mut config = test_config();
    config.storage.max_deployment_storage_bytes = Some(10);
    let system = skip_if_no_db!(test_system_with_config(config).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"a.txt","content_type":"text/plain","declared_size_bytes":50}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Negative-only coverage above would miss a quota configured so generously
/// it silently rejects everything (e.g. a unit mixup) — this pins the happy
/// path too: a fresh user, comfortably under a real-sized quota, must still
/// be able to create a session.
#[tokio::test]
async fn create_allows_a_session_within_a_configured_user_quota() {
    let mut config = test_config();
    config.storage.max_user_storage_bytes = Some(1_000_000);
    let system = skip_if_no_db!(test_system_with_config(config).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"a.txt","content_type":"text/plain","declared_size_bytes":50}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_rejects_a_malformed_checksum() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        r#"{"filename":"a.txt","content_type":"text/plain","declared_size_bytes":11,"checksum_sha256":"not-hex"}"#,
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// Exercises `files_scan::process` directly (not through the HTTP layer —
/// nothing enqueues/drains the apalis worker in this test harness). A
/// declared-checksum mismatch rejects before the scan job ever reaches the
/// clamd step, so this is fully verifiable without a reachable scanner —
/// unlike the clean-promotion and malware-positive paths, which this suite
/// does not exercise (see the file's own header comment).
#[tokio::test]
async fn scan_job_rejects_a_checksum_mismatch_without_promoting() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let wrong_checksum = "0".repeat(64);
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        &format!(
            r#"{{"filename":"data.txt","content_type":"text/plain","declared_size_bytes":11,"checksum_sha256":"{wrong_checksum}"}}"#
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    // sha256("hello world") is not all-zeros, so this will not match the
    // (deliberately wrong) declared checksum above.
    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    attome_state
        .base
        .storage
        .store()
        .put(&path, "hello world".into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");
    assert_eq!(finalized["status"], "uploaded");

    attome_document::files_scan::process(&attome_state, session_id)
        .await
        .expect("scan job must complete (checksum mismatch rejects before the clamd step)");

    let (final_status, reject_reason): (String, Option<String>) =
        sqlx::query_as("SELECT status, reject_reason FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("query session after scan");
    assert_eq!(final_status, "rejected");
    assert_eq!(
        reject_reason.as_deref(),
        Some("declared checksum does not match uploaded bytes")
    );

    // The scan result must have its own audit trail (AuditOperation::FileScanned = 25),
    // distinct from the ordinary entity-column-changed event.
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header WHERE record_id = $1 AND operation = 25",
    )
    .bind(record_id.parse::<Uuid>().unwrap())
    .fetch_one(&db)
    .await
    .expect("query audit header");
    assert_eq!(
        audit_count, 1,
        "scan result must write one FileScanned audit event"
    );
}

/// D-259's own disclosed gap, open since D-144 (2026-07-28) and closed here:
/// "clean-promotion and malware-positive scan outcomes never run against a
/// live clamd." Requires a reachable clamd (`storage.clamd_address`, not set
/// by `test_config()` by default — see `test_config_with_clamd`).
///
/// ```powershell
/// $env:TEST_CLAMD_ADDRESS = "localhost:3310"  # docker compose --profile clamav up -d clamav
/// cargo test -p attome-api --test file_upload_pipeline -- --test-threads=1 scan_job_promotes_a_clean_file
/// ```
/// `None` (after a SKIP line) when `TEST_CLAMD_ADDRESS` is not set: CI runs
/// no ClamAV sidecar, so these tests run only where one is started on purpose.
fn test_config_with_clamd() -> Option<AppConfig> {
    let Ok(address) = std::env::var("TEST_CLAMD_ADDRESS") else {
        eprintln!("SKIP: set TEST_CLAMD_ADDRESS to a running clamd to run this test");
        return None;
    };
    let mut config = test_config();
    config.storage.clamd_address = address;
    Some(config)
}

/// `test_config()` pointed at an explicit clamd address — for the tests below
/// that stand up their own in-process fake clamd on an ephemeral port instead
/// of the real sidecar (and so need no `clamav` compose profile).
fn test_config_with_clamd_at(address: &str) -> AppConfig {
    let mut config = test_config();
    config.storage.clamd_address = address.to_owned();
    config
}

/// A bound-but-not-yet-serving fake clamd. The caller needs the address
/// *before* it builds the system (the config carries it), then spawns the
/// accept loop once it holds the objects its hook needs.
async fn fake_clamd_socket() -> (tokio::net::TcpListener, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the fake clamd");
    let addr = listener.local_addr().expect("fake clamd address");
    (listener, addr)
}

/// Serves exactly one `zINSTREAM` scan on `listener`: reads the framing to its
/// zero-length terminator, awaits `hook`, then answers `reply`.
///
/// The hook is what makes BST-0c deterministic — a re-PUT of the quarantine
/// key placed *between* the bytes the scan hashed and the bytes it would
/// promote, which no timer-driven test can hit reliably.
fn serve_fake_clamd<F, Fut>(listener: tokio::net::TcpListener, reply: &'static [u8], hook: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        // `zINSTREAM\0` — 10 bytes, same command files_scan writes.
        let mut command = [0u8; 10];
        if stream.read_exact(&mut command).await.is_err() {
            return;
        }
        loop {
            let mut len = [0u8; 4];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 {
                break;
            }
            let mut chunk = vec![0u8; n];
            if stream.read_exact(&mut chunk).await.is_err() {
                return;
            }
        }
        hook().await;
        let _ = stream.write_all(reply).await;
        let _ = stream.shutdown().await;
    });
}

/// The clean half of D-259's own disclosed, previously-never-run gap: a
/// benign upload streamed through `hash_and_sniff` then re-fetched and
/// streamed into a real clamd INSTREAM scan comes back `status = 'clean'`,
/// with `final_key`/`actual_checksum_sha256` populated from the streamed
/// pass — not the whole-object-buffered pre-D-259 path this test would have
/// exercised identically either way, but proving the *rewritten* path
/// actually reaches a real scanner and promotes correctly, not just that it
/// compiles.
#[tokio::test]
async fn scan_job_promotes_a_clean_file_after_a_real_clamd_scan() {
    let Some(config) = test_config_with_clamd() else {
        return;
    };
    let system = skip_if_no_db!(test_system_with_config(config).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let content = "this is a totally clean benign test file for scanning\n";
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        &format!(
            r#"{{"filename":"clean.txt","content_type":"text/plain","declared_size_bytes":{}}}"#,
            content.len()
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    attome_state
        .base
        .storage
        .store()
        .put(&path, content.into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");

    attome_document::files_scan::process(&attome_state, session_id)
        .await
        .expect("scan job must complete against a real, reachable clamd");

    let (final_status, final_key, actual_checksum): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT status, final_key, actual_checksum_sha256 FROM upload_session WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&db)
        .await
        .expect("query session after scan");
    assert_eq!(
        final_status, "clean",
        "a benign upload must be promoted, not rejected"
    );
    assert!(
        final_key.is_some(),
        "a clean session must record its final_key"
    );
    assert!(
        actual_checksum.is_some(),
        "a clean session must record the actual streamed checksum"
    );
}

/// The malware-positive half of the same gap: the industry-standard EICAR
/// antivirus test string (safe, not real malware — every AV engine
/// including ClamAV is specifically designed to flag it) streamed through
/// the rewritten path is actually detected and rejected, not silently
/// promoted. Split into two source fragments joined at runtime rather than
/// one contiguous literal — the exact byte sequence still reaches clamd
/// unchanged, but no static scan of this source file (or the compiled test
/// binary, transiently) trips on a signature-matching string sitting in a
/// source tree rather than a deliberately-scanned object-store payload.
#[tokio::test]
async fn scan_job_rejects_the_eicar_test_string_as_malware_after_a_real_clamd_scan() {
    let eicar_part_a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-";
    let eicar_part_b = "FILE!$H+H*";
    let eicar = format!("{eicar_part_a}{eicar_part_b}");
    assert_eq!(
        eicar.len(),
        68,
        "EICAR test string must be exactly 68 bytes"
    );

    let Some(config) = test_config_with_clamd() else {
        return;
    };
    let system = skip_if_no_db!(test_system_with_config(config).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        &format!(
            r#"{{"filename":"eicar.txt","content_type":"text/plain","declared_size_bytes":{}}}"#,
            eicar.len()
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    attome_state
        .base
        .storage
        .store()
        .put(&path, eicar.clone().into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");

    attome_document::files_scan::process(&attome_state, session_id)
        .await
        .expect(
            "scan job must complete (a positive detection is a rejection outcome, not an error)",
        );

    let (final_status, reject_reason): (String, Option<String>) =
        sqlx::query_as("SELECT status, reject_reason FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("query session after scan");
    assert_eq!(
        final_status, "rejected",
        "EICAR must be detected and rejected, never promoted"
    );
    assert_eq!(reject_reason.as_deref(), Some("rejected"));

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header WHERE record_id = $1 AND operation = 25",
    )
    .bind(record_id.parse::<Uuid>().unwrap())
    .fetch_one(&db)
    .await
    .expect("query audit header");
    assert_eq!(
        audit_count, 1,
        "the malware detection must write one FileScanned audit event"
    );
}

/// `EngineJob::PruneExpiredUploadSessions`'s handler, exercised directly
/// (same reasoning as the scan-job test above — nothing drains the apalis
/// worker in this harness). Proves both halves: an abandoned `pending`
/// session past its TTL is expired, and a `legal_hold` session — no matter
/// how old — is never touched.
#[tokio::test]
async fn orphan_sweep_expires_stale_sessions_but_never_a_legal_hold_one() {
    let system = skip_if_no_db!(test_system().await);
    let (admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let stale_session_id = Uuid::now_v7();
    let held_session_id = Uuid::now_v7();
    let ancient = chrono::Utc::now() - chrono::Duration::hours(2);
    for (session_id, legal_hold) in [(stale_session_id, false), (held_session_id, true)] {
        sqlx::query(
            "INSERT INTO upload_session
                (id, entity_logicalname, record_id, field_logicalname, owner_user_ref,
                 quarantine_key, declared_filename, declared_content_type,
                 declared_max_size_bytes, status, legal_hold, created_at, updated_at)
             VALUES ($1, $2, $3, 'attachment', $4, $5, 'x.txt', 'text/plain', 1024,
                     'pending', $6, $7, $7)",
        )
        .bind(session_id)
        .bind(&logicalname)
        .bind(record_id.parse::<Uuid>().unwrap())
        .bind(admin_id)
        .bind(format!(
            "_quarantine/{logicalname}/{record_id}/attachment/{session_id}-x.txt"
        ))
        .bind(legal_hold)
        .bind(ancient)
        .execute(&db)
        .await
        .expect("insert throwaway upload session");
    }

    attome_document::files_scan::prune_expired_sessions(&attome_state)
        .await
        .expect("orphan sweep must complete");

    let stale_status: String =
        sqlx::query_scalar("SELECT status FROM upload_session WHERE id = $1")
            .bind(stale_session_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(stale_status, "expired");

    let held_status: String = sqlx::query_scalar("SELECT status FROM upload_session WHERE id = $1")
        .bind(held_session_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        held_status, "pending",
        "a legal_hold session must never be touched by the sweep, no matter how old"
    );
}

// ── Phase 0: the scan/promote race, the allowlist, and the sweep ─────────

/// BST-0c/BST-7/G-18: a re-PUT through the still-valid presigned URL after
/// finalize must never be promoted.
///
/// The fake clamd performs the re-PUT itself, so the swap lands between the
/// bytes the scan pass hashed and the bytes the promote would copy — the
/// exact window the reported defect is about, which a timer-driven test
/// cannot hit reliably. Before the ETag pin this promoted the swapped object
/// under the scanned object's checksum; after it, the promote fails closed.
#[tokio::test]
async fn a_re_put_after_finalize_is_never_promoted() {
    let (listener, clamd_addr) = fake_clamd_socket().await;
    let system = skip_if_no_db!(
        test_system_with_config(test_config_with_clamd_at(&clamd_addr.to_string())).await
    );
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let storage = system.state().base.storage.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let benign = "a totally benign file the scanner will approve\n";
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        &format!(
            r#"{{"filename":"swap.txt","content_type":"text/plain","declared_size_bytes":{}}}"#,
            benign.len()
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let quarantine_path = ObjectPath::parse(&key).expect("valid object path");
    storage
        .store()
        .put(&quarantine_path, benign.to_owned().into())
        .await
        .expect("put the benign object");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");
    assert_eq!(finalized["status"], "uploaded");

    // The swap, executed inside the scan's own clamd round trip.
    let hook_storage = storage.clone();
    let hook_path = quarantine_path.clone();
    serve_fake_clamd(listener, b"stream: OK\0", move || {
        let storage = hook_storage.clone();
        let path = hook_path.clone();
        async move {
            storage
                .store()
                .put(&path, b"<script>alert(1)</script>".to_vec().into())
                .await
                .expect("re-PUT the quarantine key while the scan is in flight");
        }
    });

    attome_document::files_scan::process(&attome_state, session_id)
        .await
        .expect("the scan job must complete, not error");

    let (final_status, reject_reason): (String, Option<String>) =
        sqlx::query_as("SELECT status, reject_reason FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("query session after scan");
    assert_eq!(
        final_status, "rejected",
        "bytes that changed after the scan pass must never be promoted"
    );
    assert_eq!(
        reject_reason.as_deref(),
        Some("uploaded object changed before it could be promoted")
    );

    // No promoted object at all, and the changed bytes are still in
    // quarantine (unknown content — kept as evidence, same posture as a
    // malware positive).
    let final_key = format!("{logicalname}/{record_id}/attachment/{session_id}-swap.txt");
    let final_path = ObjectPath::parse(&final_key).expect("valid final path");
    assert!(
        storage.store().head(&final_path).await.is_err(),
        "a swapped object must not be promoted"
    );
    assert!(
        storage.store().head(&quarantine_path).await.is_ok(),
        "the changed object must be kept in quarantine as evidence"
    );
}

/// BST-6/C1: a promoted object downloads as an `attachment` with the
/// server-chosen content type, whatever the uploader declared. Uses the fake
/// clamd replying `OK`, so no `clamav` compose profile is needed.
#[tokio::test]
async fn a_promoted_file_is_presigned_as_an_attachment() {
    let (listener, clamd_addr) = fake_clamd_socket().await;
    let system = skip_if_no_db!(
        test_system_with_config(test_config_with_clamd_at(&clamd_addr.to_string())).await
    );
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    // Deliberately *not* markup: `infer` detects HTML/XML from leading bytes,
    // and the BST-13 sniff check (rightly) rejects HTML declared as
    // `text/plain`. This test is about the promoted object's metadata, so the
    // bytes are plain text; `html_masquerading_as_plain_text_is_rejected_`
    // `before_the_scanner` below is the negative case.
    let content = "plain text notes, not markup\n";
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        &format!(
            // A filename no URL path would carry unescaped: the promoted
            // `Content-Disposition` must percent-encode it (RFC 5987).
            r#"{{"filename":"quarterly report.txt","content_type":"text/plain","declared_size_bytes":{}}}"#,
            content.len()
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    attome_state
        .base
        .storage
        .store()
        .put(&path, content.to_owned().into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");

    serve_fake_clamd(listener, b"stream: OK\0", || async {});
    attome_document::files_scan::process(&attome_state, session_id)
        .await
        .expect("scan job must complete");

    let (final_status, final_key): (String, Option<String>) =
        sqlx::query_as("SELECT status, final_key FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("query session after scan");
    assert_eq!(final_status, "clean", "the benign upload must be promoted");
    let final_key = final_key.expect("a clean session records its final_key");

    // The real download a browser would receive: a presigned GET over HTTP.
    let url = attome_storage::presign_download(
        &attome_state.base.storage,
        &final_key,
        std::time::Duration::from_secs(300),
    )
    .await
    .expect("presign download");
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("GET the presigned download URL");
    assert!(response.status().is_success());
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let disposition = header("content-disposition");
    assert!(
        disposition.starts_with("attachment"),
        "a promoted download must be an attachment, got {disposition:?}"
    );
    assert!(
        disposition.contains("filename*=UTF-8''quarterly%20report.txt"),
        "the original filename must survive, percent-encoded, got {disposition:?}"
    );
    let content_type = header("content-type");
    assert!(
        content_type.starts_with("text/plain"),
        "the scanned, allowlisted content type must be served, got {content_type:?}"
    );
}

/// BST-13/BST-F12 (G-4): HTML bytes declared as `text/plain` are caught by the
/// scan pass's own magic-byte sniff and rejected — the allowlist alone cannot
/// catch this, because the client chose a type that *is* on the list.
///
/// The clamd address points at a closed port on purpose: a job that tried to
/// reach a scanner instead of rejecting would return an error (connect
/// refused), not a rejection. That pins the decision before any scanner round
/// trip.
#[tokio::test]
async fn html_masquerading_as_plain_text_is_rejected_before_the_scanner() {
    // Nothing listens on port 1.
    let system =
        skip_if_no_db!(test_system_with_config(test_config_with_clamd_at("127.0.0.1:1")).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let content = "<html><body><script>alert(1)</script></body></html>";
    let res = create_upload_session_with_retry(
        &app,
        &admin_cookie,
        &logicalname,
        &record_id,
        &format!(
            r#"{{"filename":"innocent.txt","content_type":"text/plain","declared_size_bytes":{}}}"#,
            content.len()
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    attome_state
        .base
        .storage
        .store()
        .put(&path, content.to_owned().into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    attome_document::files_scan::process(&attome_state, session_id)
        .await
        .expect("the scan must reject, not error out trying to reach a scanner");

    let (status, reject_reason): (String, Option<String>) =
        sqlx::query_as("SELECT status, reject_reason FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("query session after scan");
    assert_eq!(
        status, "rejected",
        "HTML declared as text/plain must never be promoted"
    );
    assert_eq!(
        reject_reason.as_deref(),
        Some("uploaded object is not an allowed file type")
    );
}

/// UP-0a/UP-1.1: an `uploaded` session waiting for its scan must survive the
/// sweep however old it is, and keep its object.
///
/// The sweep used to expire `pending` *and* `uploaded` at the 15-minute
/// session TTL, so any scan backlog longer than that silently destroyed
/// legitimate uploads that still had a job queued (UP-F1).
#[tokio::test]
async fn sweep_never_expires_a_session_waiting_for_its_scan() {
    let system = skip_if_no_db!(test_system().await);
    let (admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let storage = system.state().base.storage.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let session_id = Uuid::now_v7();
    let quarantine_key =
        format!("_quarantine/{logicalname}/{record_id}/attachment/{session_id}-waiting.txt");
    let path = ObjectPath::parse(&quarantine_key).expect("valid quarantine path");
    storage
        .store()
        .put(&path, "waiting for its scan".to_owned().into())
        .await
        .expect("put the quarantine object");

    // 20 minutes old: past the 15-minute session TTL, inside the 24 h scan
    // deadline.
    let backdated = chrono::Utc::now() - chrono::Duration::minutes(20);
    sqlx::query(
        "INSERT INTO upload_session
            (id, entity_logicalname, record_id, field_logicalname, owner_user_ref,
             quarantine_key, declared_filename, declared_content_type,
             declared_max_size_bytes, status, created_at, updated_at)
         VALUES ($1, $2, $3, 'attachment', $4, $5, 'waiting.txt', 'text/plain',
                 1024, 'uploaded', $6, $6)",
    )
    .bind(session_id)
    .bind(&logicalname)
    .bind(record_id.parse::<Uuid>().unwrap())
    .bind(admin_id)
    .bind(&quarantine_key)
    .bind(backdated)
    .execute(&db)
    .await
    .expect("insert a backdated uploaded session");

    attome_document::files_scan::prune_expired_sessions(&attome_state)
        .await
        .expect("the sweep must complete");

    let status: String = sqlx::query_scalar("SELECT status FROM upload_session WHERE id = $1")
        .bind(session_id)
        .fetch_one(&db)
        .await
        .expect("query the session after the sweep");
    assert_eq!(
        status, "uploaded",
        "a queued-but-unscanned upload must never be expired by the sweep"
    );
    assert!(
        storage.store().head(&path).await.is_ok(),
        "its quarantine object must still be there"
    );
}

/// UP-0b/UP-1.2: a session whose scan never completes is `rejected` after the
/// 24 h deadline, with one `FileScanned` audit event, and its object kept —
/// unknown content, the same posture as a malware positive.
///
/// Before UP-1 a `scanning` session was never examined by the sweep, so it
/// stayed non-terminal forever (UP-F2).
#[tokio::test]
async fn a_scan_that_never_completes_is_rejected_after_the_deadline() {
    let system = skip_if_no_db!(test_system().await);
    let (admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let storage = system.state().base.storage.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;
    let record_uuid = record_id.parse::<Uuid>().unwrap();

    let session_id = Uuid::now_v7();
    let quarantine_key =
        format!("_quarantine/{logicalname}/{record_id}/attachment/{session_id}-stuck.txt");
    let path = ObjectPath::parse(&quarantine_key).expect("valid quarantine path");
    storage
        .store()
        .put(&path, "never scanned".to_owned().into())
        .await
        .expect("put the quarantine object");

    // 25 hours old: past the 24 h scan deadline.
    let backdated = chrono::Utc::now() - chrono::Duration::hours(25);
    sqlx::query(
        "INSERT INTO upload_session
            (id, entity_logicalname, record_id, field_logicalname, owner_user_ref,
             quarantine_key, declared_filename, declared_content_type,
             declared_max_size_bytes, status, claimed_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'attachment', $4, $5, 'stuck.txt', 'text/plain',
                 1024, 'scanning', $6, $6, $6)",
    )
    .bind(session_id)
    .bind(&logicalname)
    .bind(record_uuid)
    .bind(admin_id)
    .bind(&quarantine_key)
    .bind(backdated)
    .execute(&db)
    .await
    .expect("insert a backdated scanning session");

    attome_document::files_scan::prune_expired_sessions(&attome_state)
        .await
        .expect("the sweep must complete");

    let (status, reject_reason): (String, Option<String>) =
        sqlx::query_as("SELECT status, reject_reason FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("query the session after the sweep");
    assert_eq!(status, "rejected");
    assert_eq!(reject_reason.as_deref(), Some("scan did not complete"));

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header WHERE record_id = $1 AND operation = 25",
    )
    .bind(record_uuid)
    .fetch_one(&db)
    .await
    .expect("query audit header");
    assert_eq!(
        audit_count, 1,
        "a scan-deadline rejection must write exactly one FileScanned audit event"
    );
    assert!(
        storage.store().head(&path).await.is_ok(),
        "unknown content must be kept in quarantine, not deleted"
    );
}

// ── M55 P2: file versioning ─────────────────────────────────────────────

/// Drives one upload session through create -> PUT -> finalize -> a real
/// clamd scan to `clean`, returning the promoted `final_key`. Shared by the
/// versioning tests below, which each need more than one clean session on
/// the same field to exercise version 1 -> version 2 -> restore-to-1.
async fn upload_and_scan_clean_file(
    app: &axum::Router,
    attome_state: &EngineState,
    admin_cookie: &str,
    logicalname: &str,
    record_id: &str,
    filename: &str,
    content: &str,
) -> String {
    let res = create_upload_session_with_retry(
        app,
        admin_cookie,
        logicalname,
        record_id,
        &format!(
            r#"{{"filename":"{filename}","content_type":"text/plain","declared_size_bytes":{}}}"#,
            content.len()
        ),
    )
    .await;
    let status = res.status();
    let session = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session:?}");
    let session_id = Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let upload_url = session["upload_url"].as_str().unwrap().to_owned();

    let key = object_key_from_presigned_url(&upload_url, &s3_bucket());
    let path = ObjectPath::parse(&key).expect("valid object path");
    attome_state
        .base
        .storage
        .store()
        .put(&path, content.to_owned().into())
        .await
        .expect("put via object_store");

    let finalize_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");

    attome_document::files_scan::process(attome_state, session_id)
        .await
        .expect("scan job must complete against a real, reachable clamd");

    let final_key: Option<String> =
        sqlx::query_scalar("SELECT final_key FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&attome_state.base.db)
            .await
            .expect("query session after scan");
    final_key.expect("a clean session must record its final_key")
}

/// Checklist item 6, half 1: two clean writes to the same file field must
/// each create an `file_version` row (checklist item 2, the
/// finalize-path -> generic-PATCH write path exercised end to end, not
/// mocked), and restoring the first back over the second must (a) flip
/// `is_current`, (b) converge the record's live column with the restored
/// object, and (c) write exactly one `Restore` audit event
/// (`AuditOperation::Restore = 4`) for this record — the established
/// audit-event pattern this codebase already uses everywhere else
/// (`entity_crud::mutations::restore_record`, this same file's own EICAR
/// test asserting `operation = 25`), not a new one invented for this
/// feature.
#[tokio::test]
async fn version_restore_is_audited() {
    let Some(config) = test_config_with_clamd() else {
        return;
    };
    let system = skip_if_no_db!(test_system_with_config(config).await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;
    let record_uuid = record_id.parse::<Uuid>().unwrap();

    let final_key_v1 = upload_and_scan_clean_file(
        &app,
        &attome_state,
        &admin_cookie,
        &logicalname,
        &record_id,
        "v1.txt",
        "version one content\n",
    )
    .await;

    // ── PATCH attaches v1 -> creates file_version #1 ──────────
    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(format!(r#"{{"attachment":"{final_key_v1}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(patch_req).await.unwrap();
    let status = res.status();
    let patched = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "patch v1 failed: {patched:?}");
    let row_version_after_v1 = patched["row_version"].as_i64().expect("row_version");

    let final_key_v2 = upload_and_scan_clean_file(
        &app,
        &attome_state,
        &admin_cookie,
        &logicalname,
        &record_id,
        "v2.txt",
        "version two content, different bytes\n",
    )
    .await;

    // ── PATCH attaches v2 -> creates file_version #2 ──────────
    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version_after_v1}\""))
        .body(Body::from(format!(r#"{{"attachment":"{final_key_v2}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(patch_req).await.unwrap();
    let status = res.status();
    let patched = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "patch v2 failed: {patched:?}");

    let versions: Vec<(i32, bool)> = sqlx::query_as(
        "SELECT version_no, is_current FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = 'attachment'
          ORDER BY version_no",
    )
    .bind(&logicalname)
    .bind(record_uuid)
    .fetch_all(&db)
    .await
    .expect("query versions before restore");
    assert_eq!(
        versions,
        vec![(1, false), (2, true)],
        "two clean field writes must create version 1 then version 2, v2 current"
    );

    // ── Restore version 1 ────────────────────────────────────────────────
    let restore_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/versions/1/restore"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(restore_req).await.unwrap();
    let status = res.status();
    let restored = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "restore failed: {restored:?}");
    assert_eq!(restored["object_key"], final_key_v1);

    let versions_after: Vec<(i32, bool)> = sqlx::query_as(
        "SELECT version_no, is_current FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = 'attachment'
          ORDER BY version_no",
    )
    .bind(&logicalname)
    .bind(record_uuid)
    .fetch_all(&db)
    .await
    .expect("query versions after restore");
    assert_eq!(
        versions_after,
        vec![(1, true), (2, false)],
        "restore must flip version 1 back to current and clear version 2"
    );

    let live_value: Option<String> = sqlx::query_scalar(&format!(
        "SELECT attachment FROM {logicalname} WHERE id = $1"
    ))
    .bind(record_uuid)
    .fetch_one(&db)
    .await
    .expect("query record after restore");
    assert_eq!(
        live_value.as_deref(),
        Some(final_key_v1.as_str()),
        "restore must converge the record's live field value with the restored version"
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header WHERE record_id = $1 AND operation = 4",
    )
    .bind(record_uuid)
    .fetch_one(&db)
    .await
    .expect("query audit header");
    assert_eq!(
        audit_count, 1,
        "restoring a file version must write exactly one Restore audit event"
    );
}

/// Checklist item 6, half 2: item 5's retention/hold hook. A file version
/// under an active `legal_hold` must never be purged — same fail-closed
/// posture, same two columns (`legal_hold`/`retention_expires_at`), as
/// `files_scan.rs::prune_expired_sessions`'s existing gate on
/// `upload_session`. Inserts the held version row directly (no
/// clamd/RustFS dependency, mirroring `orphan_sweep_expires_stale_sessions_
/// but_never_a_legal_hold_one`'s own direct-insert style above) rather than
/// driving it through a real upload, since what this test needs to prove is
/// the gate, not the pipeline that populates the table.
#[tokio::test]
async fn hold_blocks_file_version_purge() {
    let system = skip_if_no_db!(test_system().await);
    let (admin_id, admin_cookie) = seed_admin(&system).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let (logicalname, record_id, _row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;
    let record_uuid = record_id.parse::<Uuid>().unwrap();

    let object_key = format!(
        "{logicalname}/{record_id}/attachment/{}-held.txt",
        Uuid::now_v7()
    );
    sqlx::query(
        "INSERT INTO file_version
            (entity, record_id, field, version_no, object_key, size, content_type,
             uploaded_by, scan_status, is_current, legal_hold, created_at)
         VALUES ($1, $2, 'attachment', 1, $3, 10, 'text/plain', $4, 'clean', false, true, NOW())",
    )
    .bind(&logicalname)
    .bind(record_uuid)
    .bind(&object_key)
    .bind(admin_id)
    .execute(&db)
    .await
    .expect("insert throwaway held file version");

    let purge_req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/versions/1"
        ))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(purge_req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a legal_hold file version must never be purged"
    );

    let still_there: bool = sqlx::query_scalar(
        "SELECT NOT is_deleted FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = 'attachment' AND version_no = 1",
    )
    .bind(&logicalname)
    .bind(record_uuid)
    .fetch_one(&db)
    .await
    .expect("query version after refused purge");
    assert!(
        still_there,
        "a refused purge must not mark the held version row deleted"
    );
}
