//! D-364 — integration coverage for the two pieces of the Documents feature
//! that need a real Postgres + RustFS + clamd to prove, mirroring
//! `file_upload_pipeline.rs`'s harness (this suite needs the same real
//! object-storage round-trip, plus a reachable `clamd` — unlike that file's
//! default suite, both new tests here need a truly `clean` session, since
//! `entity_mutation::lock_file_field_sessions` only accepts one, so
//! `test_config_with_clamd`/`files_scan::process` are used unconditionally
//! rather than being a separate opt-in test):
//!
//! 1. `sync_file_field_documents` (`entity_crud/mutations.rs`) — a record's
//!    file-typed field, once PATCHed to a clean key, mirrors into a new
//!    `attome_document` row with the right `source_field`/`folder`; clearing the
//!    field soft-deletes that mirror.
//! 2. `hard_delete_record`'s storage cleanup — hard-deleting an `attome_document`
//!    row with a `file` value actually removes the RustFS object, not just
//!    the row.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! $env:S3_ACCESS_KEY = "..."; $env:S3_SECRET_KEY = "..."
//! cargo test -p attome-api --test document_management -- --test-threads=1
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
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use object_store::ObjectStoreExt;
use object_store::path::Path as ObjectPath;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

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

/// Needs a reachable `clamd` (`storage.clamd_address`) — both tests in this
/// file must reach a real `clean` session, unlike most of
/// `file_upload_pipeline.rs`'s suite. Defaults to `localhost:3310`, the
/// `docker compose --profile clamav up -d clamav` port.
fn test_config() -> AppConfig {
    let access_key = std::env::var("S3_ACCESS_KEY").expect(
        "set S3_ACCESS_KEY to a real RustFS/MinIO credential to run document_management tests",
    );
    let secret_key = std::env::var("S3_SECRET_KEY").expect(
        "set S3_SECRET_KEY to a real RustFS/MinIO credential to run document_management tests",
    );
    let clamd_address =
        std::env::var("TEST_CLAMD_ADDRESS").unwrap_or_else(|_| "localhost:3310".into());

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
                "max_upload_size_bytes": 1048576, "clamd_address": "{clamd_address}"
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

async fn test_system() -> Option<EngineSystem> {
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
        .bind(format!("document-mgmt-test-admin-{user_id}"))
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

async fn create_field(app: &axum::Router, admin_cookie: &str, entity_id: &str, body: &str) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create field");
    assert_eq!(res.status(), StatusCode::CREATED, "create field: {body}");
}

/// `attome_document` with its full production shape (D-364) comes from
/// `platform-bundles/attome-document.json`, applied when the system is built, so
/// the test no longer provisions it (a second `POST /admin/entities` is a
/// 409). This checks the bundle's entity is served before the write paths run.
async fn provision_xrm_document(app: &axum::Router, admin_cookie: &str) {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/entities?page_size=500")
        .header("cookie", admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("list entities");
    assert_eq!(res.status(), StatusCode::OK, "list entities");
    let listed = body_json(res).await;
    let present = listed["items"]
        .as_array()
        .is_some_and(|items| items.iter().any(|e| e["logicalname"] == "attome_document"));
    assert!(
        present,
        "the attome-document platform bundle must provide attome_document: {listed}"
    );
}

/// Provisions an entity with a required `title` field and an optional
/// `attachment` file field, then creates one record on it (matching
/// `file_upload_pipeline.rs::provision_entity_with_file_field`'s shape).
/// Returns (logicalname, record_id, row_version).
async fn provision_entity_with_file_field(
    app: &axum::Router,
    admin_cookie: &str,
) -> (String, String, i64) {
    let logicalname = format!("doc_mgmt_{}", Uuid::now_v7().simple());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Doc Mgmt Test"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    create_field(
        app,
        admin_cookie,
        &entity_id,
        r#"{"logicalname":"title","name":"Title","field_type":"text","is_required":true}"#,
    )
    .await;
    create_field(
        app,
        admin_cookie,
        &entity_id,
        r#"{"logicalname":"attachment","name":"Attachment","field_type":"file"}"#,
    )
    .await;

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

async fn create_upload_session_with_retry(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
    field: &str,
    body: &str,
) -> axum::response::Response {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{logicalname}/{record_id}/files/{field}/upload-session"
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

/// Drives one file all the way to a `clean`, PATCH-able key: create session
/// -> put the real bytes via `object_store` -> finalize -> run the scan job
/// synchronously against a real `clamd` (`files_scan::process`, same call
/// `file_upload_pipeline.rs::scan_job_promotes_a_clean_file_after_a_real_clamd_scan`
/// uses) -> return the `final_key`.
#[allow(clippy::too_many_arguments)]
async fn upload_clean_file(
    app: &axum::Router,
    attome_state: &EngineState,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
    field: &str,
    filename: &str,
    content: &str,
) -> String {
    let res = create_upload_session_with_retry(
        app,
        cookie,
        logicalname,
        record_id,
        field,
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
            "/api/v1/{logicalname}/{record_id}/files/{field}/upload-session/{session_id}/finalize"
        ))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(finalize_req).await.unwrap();
    let status = res.status();
    let finalized = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {finalized:?}");

    attome_document::files_scan::process(attome_state, session_id)
        .await
        .expect("scan job must complete against a real, reachable clamd");

    let (final_status, final_key): (String, Option<String>) =
        sqlx::query_as("SELECT status, final_key FROM upload_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&attome_state.base.db)
            .await
            .expect("query session after scan");
    assert_eq!(final_status, "clean", "upload must be promoted to clean");
    final_key.expect("clean session must carry a final_key")
}

/// D-364: a record's own file-typed field, once PATCHed to a clean key,
/// mirrors into a new `attome_document` row (`sync_file_field_documents`,
/// `entity_crud/mutations.rs`) with `source_field` naming the field and
/// `folder` defaulted to `uploads`; clearing the field soft-deletes that
/// mirror rather than leaving it behind.
#[tokio::test]
async fn file_field_write_mirrors_into_xrm_document_and_clearing_it_soft_deletes_the_mirror() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    provision_xrm_document(&app, &admin_cookie).await;
    let (logicalname, record_id, row_version) =
        provision_entity_with_file_field(&app, &admin_cookie).await;

    let final_key = upload_clean_file(
        &app,
        &attome_state,
        &admin_cookie,
        &logicalname,
        &record_id,
        "attachment",
        "mirror-test.txt",
        "mirror sync test content",
    )
    .await;

    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(format!(r#"{{"attachment":"{final_key}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(patch_req).await.unwrap();
    let status = res.status();
    let patched = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "patch failed: {patched:?}");

    let mirror: Option<(Uuid, String, String, bool)> = sqlx::query_as(
        "SELECT id, folder, source_field, is_active FROM attome_document \
         WHERE entity_name = $1 AND record_id = $2",
    )
    .bind(&logicalname)
    .bind(&record_id)
    .fetch_optional(&db)
    .await
    .expect("query attome_document for mirror");
    let (mirror_id, folder, source_field, is_active) =
        mirror.expect("file field write must have mirrored into attome_document");
    assert_eq!(
        folder, "uploads",
        "manual uploads default to the uploads folder"
    );
    assert_eq!(
        source_field, "attachment",
        "mirror must name the field it came from"
    );
    assert!(is_active, "freshly mirrored row must be active");

    // Clearing the field must soft-delete the mirror, not leave it dangling.
    let clear_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", "\"1\"")
        .body(Body::from(r#"{"attachment":null}"#))
        .unwrap();
    let res = app.clone().oneshot(clear_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "clear-field patch failed");

    let is_active_after: bool =
        sqlx::query_scalar("SELECT is_active FROM attome_document WHERE id = $1")
            .bind(mirror_id)
            .fetch_one(&db)
            .await
            .expect("query mirror after clearing the field");
    assert!(
        !is_active_after,
        "clearing the source field must soft-delete its mirror"
    );
}

/// D-364: `hard_delete_record`'s storage cleanup actually removes the RustFS
/// object behind a `file`-typed column, not just the row — the gap that
/// blocked this test until the pre-existing, unrelated `audit_snapshot`
/// jsonb/text mismatch (found while building this feature) was fixed
/// separately: every hard-delete's own audit write failed and rolled the
/// whole transaction back, so this cleanup code was previously unreachable.
#[tokio::test]
async fn hard_delete_removes_the_storage_object_behind_a_file_field() {
    let system = skip_if_no_db!(test_system().await);
    let (_admin_id, admin_cookie) = seed_admin(&system).await;
    let attome_state = system.state().clone();
    let app = full_app(system);

    provision_xrm_document(&app, &admin_cookie).await;

    let create_req = Request::builder()
        .method("POST")
        .uri("/api/v1/attome_document")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"hd-test.txt","entity_name":"attome_document","record_id":"00000000-0000-0000-0000-000000000001","folder":"uploads"}"#,
        ))
        .unwrap();
    let res = app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let doc_id = created["id"].as_str().unwrap().to_owned();
    let row_version = created["row_version"].as_i64().unwrap();

    let final_key = upload_clean_file(
        &app,
        &attome_state,
        &admin_cookie,
        "attome_document",
        &doc_id,
        "file",
        "hd-test.txt",
        "hard delete storage cleanup test",
    )
    .await;

    let patch_req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/attome_document/{doc_id}"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(format!(r#"{{"file":"{final_key}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(patch_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "attach file key failed");

    let path = ObjectPath::parse(&final_key).expect("valid object path");
    assert!(
        attome_state.base.storage.store().head(&path).await.is_ok(),
        "object must exist before hard-delete"
    );

    let hard_delete_req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/attome_document/{doc_id}/hard-delete"))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(hard_delete_req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "hard-delete must succeed now that the audit-snapshot write is fixed"
    );

    // Best-effort cleanup runs after commit — give it a moment, same
    // tolerance file_upload_pipeline.rs's own storage-deletion assertions
    // don't need (those run inline), but this one is a separate loop after
    // the HTTP response.
    let mut gone = false;
    for _ in 0..10 {
        if attome_state.base.storage.store().head(&path).await.is_err() {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(
        gone,
        "hard-delete must remove the storage object, not just the row"
    );

    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/attome_document/{doc_id}"))
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "row must be gone too");
}
