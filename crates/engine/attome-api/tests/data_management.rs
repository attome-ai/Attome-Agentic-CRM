//! M12 (data management) — regression coverage for `data_export.rs`'s
//! permission-filtered export and `bulk.rs`'s mapping-driven staged import.
//!
//! Covers:
//! - export never includes a column the caller lacks a field-read grant on
//!   (D-408's central invariant) — verified by actually reading the
//!   uploaded object back out of the object store, not just inspecting the
//!   plan/query builder;
//! - a staged-import `mapping_ref` whose lookup resolution fails for one
//!   record is a per-item `rejected` finding, not a whole-batch 422 — the
//!   same isolation `bulk_graph::run_preflight`'s findings already get
//!   (`bulk_mutation.rs` covers that half); this file covers mapping
//!   resolution failures specifically.
//!
//! Harness copied near-verbatim from `bulk_mutation.rs`/`record_level_security.rs`
//! (same convention every integration suite in this crate follows — see
//! those files' own headers for why it isn't factored into a shared
//! module).
//!
//! Requires a live Postgres (`DATABASE_URL`), Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), and object store (`localhost:9000`, RustFS/MinIO) —
//! same convention as `bulk_mutation.rs`/`file_upload_pipeline.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test data_management -- --test-threads=1
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
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (copied near-verbatim from bulk_mutation.rs) ────────────────────

fn test_config(db: &DbUrlParts) -> AppConfig {
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
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }},
                "readonly": {{ "user": "attome_readonly", "password": "{readonly_password}" }}
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "{s3_endpoint}", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}", "s3_secret_key": "{s3_secret_key}",
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
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
        readonly_password = READONLY_PASSWORD,
        // `TEST_S3_ENDPOINT` moves the object store off the dev store's port.
        s3_endpoint =
            std::env::var("TEST_S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into()),
        s3_access_key = attome_testkit::s3_env("S3_ACCESS_KEY"),
        s3_secret_key = attome_testkit::s3_env("S3_SECRET_KEY"),
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// The `attome_readonly` login this suite sets, for the long pool (AB6-T6).
const READONLY_PASSWORD: &str = "test-only-readonly-password";

/// Gives `attome_readonly` a login with [`READONLY_PASSWORD`] (the role
/// exists from the migrations; only its password is per test database).
async fn synchronize_readonly_login(db: &attome_db::DbPool) {
    sqlx::query(&format!(
        "ALTER ROLE attome_readonly WITH LOGIN PASSWORD '{READONLY_PASSWORD}'"
    ))
    .execute(db)
    .await
    .expect("give attome_readonly a test login");
}

async fn test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let config = test_config(&DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse"));
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
    // AB6-T6: exports read through the long pool, as at boot.
    synchronize_readonly_login(&db).await;
    let db_long = attome_db::create_long_pool(&config)
        .await
        .expect("connect the long pool");
    let base = AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    )
    .with_long_pool(db_long);
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

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("dm-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("dm-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");

    if admin {
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
    }

    (user_id, email, session_cookie(user_id))
}

async fn seed_non_admin_user(db: &attome_db::DbPool) -> (Uuid, String, String) {
    let user_id = Uuid::now_v7();
    let email = format!("dm-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("dm-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email, session_cookie(user_id))
}

async fn grant_privilege(
    app: &axum::Router,
    admin_cookie: &str,
    user_email: &str,
    privilege_key: &str,
) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/security/grants",
            admin_cookie,
            Some(&json!({ "user_email": user_email, "privilege_key": privilege_key })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "grant {privilege_key} to {user_email}"
    );
}

async fn seed_scoped_user(
    db: &attome_db::DbPool,
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    actions: &[&str],
) -> (Uuid, String, String) {
    let (user_id, email, cookie) = seed_non_admin_user(db).await;
    for action in actions {
        grant_privilege(
            app,
            admin_cookie,
            &email,
            &format!("{logicalname}.{action}"),
        )
        .await;
    }
    (user_id, email, cookie)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn req(method: &str, uri: &str, cookie: &str, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

/// Creates an entity with a plain `title` text field and an `is_sensitive`
/// `secret` text field — no `field_security_profile` row is ever
/// created for it, so `has_field_read_grant` resolves `false` for every
/// non-admin caller (the absent-grant-means-no-access default, same as
/// `merge_rejects_when_a_dependent_sensitive_field_lacks_write_grant` in
/// `record_level_security.rs` relies on).
async fn provision_entity_with_sensitive_field(
    app: &axum::Router,
    admin_cookie: &str,
    prefix: &str,
) -> (String, Uuid) {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({ "logicalname": logicalname, "name": "Data Management Test" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity = body_json(res).await;
    let entity_id: Uuid = entity["id"].as_str().unwrap().parse().unwrap();

    for (ln, sensitive) in [("title", false), ("secret", true)] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(&json!({
                    "logicalname": ln, "name": ln, "field_type": "text",
                    "is_sensitive": sensitive,
                })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {ln}");
    }

    (logicalname, entity_id)
}

/// Tests disable the background metadata registry subscriber, so lookup
/// validation needs an explicit refresh after dynamically provisioning a
/// lookup field — same helper/rationale as `record_level_security.rs`.
async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build metadata registry");
    state.entities.swap(registry);
}

/// M12/D-408 — the central export invariant: a caller with `{entity}.read`
/// but no field-read grant on an `is_sensitive` column never sees that
/// column's name or value in the exported file, whatever format it asked
/// for. Verified by actually downloading the uploaded object from the
/// object store and inspecting its raw bytes — not by inspecting
/// `plan_export`'s query builder in isolation, which would only prove the
/// SQL looked right, not that the file on disk actually reflects it.
#[tokio::test]
async fn export_never_includes_a_field_the_caller_lacks_field_read_grant_for() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let storage = system.state().base.storage.clone();
    let state = system.state().clone();
    let (_admin_id, _admin_email, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let (logicalname, _entity_id) =
        provision_entity_with_sensitive_field(&app, &admin_cookie, "dm_exp").await;

    // Non-admin caller: `{entity}.read` only, no field-security profile at
    // all for `secret` — `has_field_read_grant` therefore resolves `false`
    // for it (the absent-grant default).
    let (caller_user_id, _email, caller_cookie) =
        seed_scoped_user(&db, &app, &admin_cookie, &logicalname, &["read"]).await;

    // Seed the fixture record directly (throwaway DB, sanctioned exemption,
    // testing skill) rather than through the create API — the admin
    // cookie could create it either way, but this keeps the fixture setup
    // independent of `entity_mutation::validate_field_write_grants`'s own
    // behavior, which this test isn't exercising.
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (title, secret) VALUES ($1, $2)"
    ))
    .bind("Public Value")
    .bind("Hidden Value")
    .execute(&db)
    .await
    .expect("insert fixture record");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/export"),
            &caller_cookie,
            Some(&json!({ "format": "json", "columns": [], "filter": [] })),
        ))
        .await
        .expect("enqueue export");
    assert_eq!(res.status(), StatusCode::ACCEPTED, "enqueue export");
    let enqueued = body_json(res).await;
    let export_id: Uuid = enqueued["id"].as_str().unwrap().parse().unwrap();

    // Drive the worker deterministically instead of waiting on a live
    // Apalis worker — same convention `bulk_mutation.rs` uses for
    // `bulk::process`. `columns: vec![]` matches what the real enqueue
    // handler would have already narrowed to (it also re-derives via
    // `plan_export`), so this exercises the identical security path either
    // way.
    attome_api::data_export::process(
        &state,
        attome_core::jobs::DataExportPayload {
            export_id,
            entity_logicalname: logicalname.clone(),
            format: "json".to_string(),
            columns: vec![],
            filters: vec![],
            user_id: caller_user_id,
        },
    )
    .await
    .expect("run export job");

    let object_key: Option<String> = sqlx::query_scalar(
        "SELECT object_key FROM data_export WHERE id = $1 AND status = 'completed'",
    )
    .bind(export_id)
    .fetch_optional(&db)
    .await
    .expect("query export row")
    .flatten();
    let object_key = object_key.expect("export must have completed with an object_key");

    let path = ObjectPath::parse(&object_key).expect("valid object key");
    let bytes = storage
        .store()
        .get(&path)
        .await
        .expect("download exported object")
        .bytes()
        .await
        .expect("read exported object body");
    let content = String::from_utf8(bytes.to_vec()).expect("exported file must be UTF-8");

    assert!(
        content.contains("Public Value"),
        "the field the caller CAN read must still be exported: {content}"
    );
    assert!(
        !content.contains("secret") && !content.contains("Hidden Value"),
        "an is_sensitive field with no field-read grant must never appear in the exported \
         file, neither its name nor its value: {content}"
    );
}

/// AB6-T6: an export streams its rows through the long pool (the read-only
/// role, `attome-long`), so it holds no interactive connection while it
/// uploads. It completes with every row through that pool; with the long
/// pool closed, the same export fails, so the rows come from nowhere else.
#[tokio::test]
async fn export_uses_long_pool() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let state = system.state().clone();
    let (admin_id, _email, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _entity_id) =
        provision_entity_with_sensitive_field(&app, &admin_cookie, "dm_long").await;
    for n in 0..3 {
        sqlx::query(&format!(
            "INSERT INTO \"{logicalname}\" (title) VALUES ($1)"
        ))
        .bind(format!("Row {n}"))
        .execute(&db)
        .await
        .expect("insert fixture record");
    }
    let export = |app: axum::Router| {
        let state = state.clone();
        let logicalname = logicalname.clone();
        let admin_cookie = admin_cookie.clone();
        async move {
            let res = app
                .oneshot(req(
                    "POST",
                    &format!("/api/v1/{logicalname}/export"),
                    &admin_cookie,
                    Some(&json!({ "format": "csv", "columns": [], "filter": [] })),
                ))
                .await
                .expect("enqueue export");
            assert_eq!(res.status(), StatusCode::ACCEPTED, "enqueue export");
            let export_id: Uuid = body_json(res).await["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            attome_api::data_export::process(
                &state,
                attome_core::jobs::DataExportPayload {
                    export_id,
                    entity_logicalname: logicalname,
                    format: "csv".to_string(),
                    columns: vec![],
                    filters: vec![],
                    user_id: admin_id,
                },
            )
            .await
            .expect("run export job");
            sqlx::query_as::<_, (String, Option<i64>)>(
                "SELECT status, row_count FROM data_export WHERE id = $1",
            )
            .bind(export_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read the export row")
        }
    };

    let (status, rows) = export(app.clone()).await;
    assert_eq!((status.as_str(), rows), ("completed", Some(3)));

    let long = state
        .base
        .db_long
        .clone()
        .expect("the long pool is attached");
    long.close().await;
    let (status, _) = export(app).await;
    assert_eq!(
        status, "failed",
        "with the long pool closed the export has nowhere to read from"
    );
}

/// M12 — a mapping-driven staged import whose lookup resolution fails for
/// one record (an unresolvable `by_natural_key` value) is reported as that
/// record's own `rejected` finding, not a whole-batch failure — the other,
/// resolvable record still passes its dry run. Mirrors the isolation
/// `bulk_mutation.rs` already proves for `bulk_graph::run_preflight`
/// findings, specifically for mapping resolution errors.
#[tokio::test]
async fn staged_import_mapping_resolution_failure_is_a_per_item_rejection_not_a_whole_batch_failure()
 {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let state = system.state().clone();
    let (_admin_id, _admin_email, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    // The referenced ("manager") entity — matched by its `code` field for
    // `by_natural_key` resolution.
    let manager_name = format!("dm_map_mgr_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            &admin_cookie,
            Some(&json!({ "logicalname": manager_name, "name": "Mapping Test Manager" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let manager_entity = body_json(res).await;
    let manager_entity_id: Uuid = manager_entity["id"].as_str().unwrap().parse().unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{manager_entity_id}/fields"),
            &admin_cookie,
            Some(&json!({ "logicalname": "code", "name": "code", "field_type": "text" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{manager_name}"),
            &admin_cookie,
            Some(&json!({ "code": "MGR1" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // The target entity: a plain text field plus a lookup to the manager.
    let target_name = format!("dm_map_tgt_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            &admin_cookie,
            Some(&json!({ "logicalname": target_name, "name": "Mapping Test Target" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let target_entity = body_json(res).await;
    let target_entity_id: Uuid = target_entity["id"].as_str().unwrap().parse().unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{target_entity_id}/fields"),
            &admin_cookie,
            Some(&json!({ "logicalname": "full_name", "name": "full_name", "field_type": "text" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{target_entity_id}/fields"),
            &admin_cookie,
            Some(&json!({
                "logicalname": "manager_ref", "name": "manager_ref", "field_type": "lookup",
                "lookup_entity_ref": manager_entity_id,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    sync_registry(&state).await;

    let (_user_id, _email, caller_cookie) = seed_scoped_user(
        &db,
        &app,
        &admin_cookie,
        &target_name,
        &["read", "create", "update", "delete", "bulk"],
    )
    .await;

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/data/mappings",
            &admin_cookie,
            Some(&json!({
                "name": format!("dm-map-{}", Uuid::now_v7()),
                "target_entity": target_name,
                "source_kind": "json",
                "fields": [
                    { "source": "full_name", "target": "full_name", "lookup_resolution": "by_id" },
                    {
                        "source": "manager_code", "target": "manager_ref",
                        "lookup_resolution": "by_natural_key", "lookup_match_field": "code",
                    },
                ],
            })),
        ))
        .await
        .expect("create mapping");
    assert_eq!(res.status(), StatusCode::CREATED, "create mapping");
    let mapping = body_json(res).await;
    let mapping_id = mapping["id"].as_str().expect("mapping id").to_string();

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{target_name}/staged-import"),
            &caller_cookie,
            Some(&json!({
                "operation": "create",
                "mapping_ref": mapping_id,
                "records": [
                    { "data": { "full_name": "Alice", "manager_code": "MGR1" } },
                    { "data": { "full_name": "Bob", "manager_code": "NOPE" } },
                ],
            })),
        ))
        .await
        .expect("submit staged import");
    assert_eq!(
        res.status(),
        StatusCode::ACCEPTED,
        "an unresolvable mapping lookup on one record must not 422 the whole submission"
    );
    let result = body_json(res).await;
    assert_eq!(result["total"], 2);
    assert_eq!(
        result["rejected"], 1,
        "Bob's unresolvable manager_code must be reported as a per-item rejection: {result:?}"
    );
    assert_eq!(
        result["passed"], 1,
        "Alice's record must still dry-run successfully despite Bob's failure: {result:?}"
    );
}

/// D-606 (CSV import): the wizard saves its column mapping under a name the
/// user types. `uq_core_data_mapping_name` makes a second live mapping with
/// that name a clash with existing state, so both create and a rename onto it
/// answer 409 Conflict — before this they were masked as a 500.
#[tokio::test]
async fn duplicate_mapping_name_is_a_409_conflict_not_a_500() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let (_admin_id, _admin_email, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let target_name = format!("dm_dup_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            &admin_cookie,
            Some(&json!({ "logicalname": target_name, "name": "Mapping Name Clash" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            &admin_cookie,
            Some(&json!({ "logicalname": "full_name", "name": "full_name", "field_type": "text" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    sync_registry(&state).await;

    let name = format!("dm-dup-{}", Uuid::now_v7());
    let body = |n: &str| {
        json!({
            "name": n,
            "target_entity": target_name,
            "source_kind": "csv",
            "fields": [{ "source": "Full name", "target": "full_name" }],
        })
    };
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/data/mappings",
            &admin_cookie,
            Some(&body(&name)),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "first mapping");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/data/mappings",
            &admin_cookie,
            Some(&body(&name)),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a second live mapping with the same name must be a 409, not a masked 500"
    );
    assert_eq!(body_json(res).await["error"], "conflict");

    let other = format!("dm-dup-other-{}", Uuid::now_v7());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/data/mappings",
            &admin_cookie,
            Some(&body(&other)),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "second, distinct mapping"
    );
    let other_id = body_json(res).await["id"].as_str().unwrap().to_string();
    let res = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/v1/admin/data/mappings/{other_id}"),
            &admin_cookie,
            Some(&json!({ "name": name })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "renaming onto a live mapping's name must be a 409 too"
    );
}
