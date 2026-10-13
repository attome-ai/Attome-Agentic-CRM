//! Integration tests for the changeset authoring routes (Solution 7 Phase 1,
//! D-785, design §4.6 and §7): open / list / show / close / abandon / export
//! over `/api/v1/admin/changesets`.
//!
//! Operations are recorded through the real recorder
//! (`attome_core::changeset::Recording`) with snapshots in the column
//! shape `crate::changeset::translate` documents, so these tests do not
//! depend on the admin-route hooks (lanes L3–L5). Direct SQL is used only to
//! seed users and a metadata change-log row in the throwaway test database
//! (coding-guidelines.md §4's test exemption).
//!
//! Requires a live Postgres (`DATABASE_URL`, migrated through 0522) and Redis:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test changeset_routes -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::changeset::jcs;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, RecordedOp, Recording, RecordingMode, RequestContext};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
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
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &url);
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
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));
    Some(system)
}

#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            let base_state = state.base.clone();
            let app =
                attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
                    .add_bundle(system.core_routes())
                    .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
            Some(TestSystem { state, app })
        })
        .await
        .clone()
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

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("changeset-test-{user_id}"))
    .bind(format!("cs-{user_id}@test.local"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded");
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

fn request(
    method: &str,
    uri: &str,
    cookie: &str,
    if_match: Option<i64>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(v) = if_match {
        builder = builder.header("if-match", format!("\"{v}\""));
    }
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    builder.body(body).expect("request")
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn unique(prefix: &str) -> String {
    let hex = Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &hex[hex.len() - 10..])
}

async fn open(app: &axum::Router, cookie: &str, scope: &str, name: &str) -> Value {
    let (status, body) = send(
        app,
        request(
            "POST",
            "/api/v1/admin/changesets",
            cookie,
            None,
            Some(json!({
                "layer": "project", "scope": scope, "name": name,
                "title": "Test changeset", "description": "Integration test",
                "requires": { "modules": ["core"] },
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

fn recording(actor: Uuid, header: Option<Uuid>, mode: RecordingMode) -> Recording {
    Recording::for_request(RequestContext {
        header,
        actor: Some(actor),
        actor_label: format!("user:{actor}"),
        request_id: Some("req-test".into()),
        route: "POST /api/v1/admin/apps".into(),
        mode,
        auto_layer: Layer::Project,
        break_glass: false,
    })
}

fn app_op(app: &str) -> RecordedOp {
    RecordedOp {
        op: Op::UpsertApp,
        object_kind: "app",
        object_ref: Some(Uuid::now_v7()),
        target: json!({ "app": app }),
        snapshot: json!({
            "id": Uuid::now_v7(), "name": app, "icon": "las la-th-large",
            "entities": ["contract"], "roles": [], "display_order": 1,
            "is_active": true, "row_version": 1,
        }),
        changed: vec![],
    }
}

fn retire_view_op(entity: &str, view: &str) -> RecordedOp {
    RecordedOp {
        op: Op::RetireView,
        object_kind: "view",
        object_ref: Some(Uuid::now_v7()),
        target: json!({ "entity": entity, "view": view }),
        snapshot: json!({ "name": view, "is_active": false }),
        changed: vec![],
    }
}

async fn record(state: &EngineState, recording: &Recording, op: RecordedOp) {
    recording
        .preflight(&state.base.db)
        .await
        .expect("preflight");
    let mut tx = attome_db::tx::begin(&state.base.db).await.expect("begin");
    recording.record(&mut tx, op).await.expect("record");
    attome_db::tx::commit(tx).await.expect("commit");
}

#[test]
fn open_list_and_the_name_rule() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system.state.base.db).await;
        let scope = unique("s");
        let name = unique("n");
        let opened = open(&system.app, &cookie, &scope, &name).await;
        assert_eq!(opened["status"], "open");
        assert_eq!(opened["origin"], "authored");
        assert_eq!(opened["author_ref"], json!(actor));
        assert_eq!(
            opened["author_label"],
            json!(format!("cs-{actor}@test.local"))
        );

        // A second open changeset with the same layer, scope and name.
        let (status, body) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/changesets",
                &cookie,
                None,
                Some(json!({ "layer": "project", "scope": scope, "name": name, "title": "Again" })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.to_string().contains("changeset_name_taken"), "{body}");

        // Invalid input is a 422, never a 500.
        for bad in [
            json!({ "layer": "customer", "scope": "acme", "name": "x", "title": "T" }),
            json!({ "layer": "platform", "scope": "acme", "name": "x", "title": "T" }),
            json!({ "layer": "project", "scope": "Acme", "name": "x", "title": "T" }),
            json!({ "layer": "project", "scope": "acme", "name": "x", "title": "T",
                    "requires": { "platform": "4" } }),
        ] {
            let (status, body) = send(
                &system.app,
                request(
                    "POST",
                    "/api/v1/admin/changesets",
                    &cookie,
                    None,
                    Some(bad.clone()),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad} -> {body}");
        }

        let (status, list) = send(
            &system.app,
            request(
                "GET",
                &format!("/api/v1/admin/changesets?scope={scope}&status=open&page=1&page_size=10"),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list["total"], 1);
        assert_eq!(list["page"], 1);
        assert_eq!(list["items"][0]["id"], opened["id"]);

        let (status, _) = send(
            &system.app,
            request(
                "GET",
                "/api/v1/admin/changesets?status=sometimes",
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Tidy: abandon it (empty).
        let (status, abandoned) = send(
            &system.app,
            request(
                "POST",
                &format!(
                    "/api/v1/admin/changesets/{}/abandon",
                    opened["id"].as_str().expect("id")
                ),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{abandoned}");
        assert_eq!(abandoned["status"], "abandoned");
    });
}

#[test]
fn close_translates_checksums_and_summarizes() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = &system.state;
        let (actor, cookie) = seed_admin(&state.base.db).await;
        let opened = open(&system.app, &cookie, &unique("s"), &unique("n")).await;
        let id: Uuid = opened["id"].as_str().expect("id").parse().expect("uuid");
        let uri = |suffix: &str| format!("/api/v1/admin/changesets/{id}{suffix}");

        // Empty: close refuses, and the refusal comes before any work.
        let (status, body) = send(
            &system.app,
            request("POST", &uri("/close"), &cookie, Some(0), None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.to_string().contains("changeset_empty"), "{body}");

        let rec = recording(actor, Some(id), RecordingMode::Required);
        record(state, &rec, app_op("sales")).await;
        record(state, &rec, retire_view_op("contract", "Old")).await;

        // Not empty any more: abandon refuses.
        let (status, body) = send(
            &system.app,
            request("POST", &uri("/abandon"), &cookie, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.to_string().contains("changeset_not_empty"), "{body}");

        let (status, detail) =
            send(&system.app, request("GET", &uri(""), &cookie, None, None)).await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["changeset"]["op_count"], 2);
        assert_eq!(detail["operations"][0]["op"], "upsert_app");
        assert_eq!(detail["operations"][1]["phase"], "contract");
        assert!(detail["document"].is_null());
        let version = detail["changeset"]["row_version"]
            .as_i64()
            .expect("row_version");

        // Export before close.
        let (status, _) = send(
            &system.app,
            request("GET", &uri("/export"), &cookie, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // If-Match is mandatory and must be current.
        let (status, _) = send(
            &system.app,
            request("POST", &uri("/close"), &cookie, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = send(
            &system.app,
            request("POST", &uri("/close"), &cookie, Some(version - 1), None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, closed) = send(
            &system.app,
            request("POST", &uri("/close"), &cookie, Some(version), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{closed}");
        let document = &closed["changeset"];
        assert_eq!(document["format"], "attome-changeset/v1");
        assert_eq!(document["id"], json!(id));
        assert_eq!(document["layer"], "project");
        assert_eq!(document["requires"]["modules"], json!(["core"]));
        assert!(
            document["requires"]["platform"]
                .as_str()
                .is_some_and(|p| p.starts_with(">=")),
            "{document}"
        );
        assert_eq!(
            document["checksum"].as_str(),
            Some(jcs::document_checksum(document).expect("checksum").as_str()),
            "the stored checksum is the JCS checksum of the document"
        );
        let ops = document["operations"].as_array().expect("operations");
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0]["seq"], 1);
        assert_eq!(ops[0]["target"], json!({ "app": "sales" }));
        let definition = &ops[0]["args"]["definition"];
        assert_eq!(definition["name"], "sales");
        assert_eq!(definition["entities"], json!(["contract"]));
        assert!(definition.get("id").is_none() && definition.get("row_version").is_none());
        assert!(ops[1].get("args").is_none(), "a retire op carries no args");
        let summary = closed["summary"].as_str().expect("summary");
        assert!(
            summary.contains("1. Create or update the app \"sales\"."),
            "{summary}"
        );
        assert!(
            summary.contains("2. Remove the view \"Old\" from \"contract\"."),
            "{summary}"
        );
        assert!(summary.contains("## Look closely"), "{summary}");

        // Args were filled once; export returns the same document.
        let (status, detail) =
            send(&system.app, request("GET", &uri(""), &cookie, None, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["changeset"]["status"], "closed");
        assert!(detail["operations"][0]["args"]["definition"].is_object());
        let (status, exported) = send(
            &system.app,
            request("GET", &uri("/export"), &cookie, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&exported, document);

        // Closed is final: no second close, no abandon, no further recording.
        let (status, _) = send(
            &system.app,
            request("POST", &uri("/close"), &cookie, Some(version + 1), None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let late = recording(actor, Some(id), RecordingMode::Required);
        assert!(late.preflight(&state.base.db).await.is_err());
    });
}

#[test]
fn close_warns_about_unrecorded_entity_changes() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = &system.state;
        let (actor, cookie) = seed_admin(&state.base.db).await;
        let opened = open(&system.app, &cookie, &unique("s"), &unique("n")).await;
        let id: Uuid = opened["id"].as_str().expect("id").parse().expect("uuid");

        // An entity change the recorder never saw.
        let stray = unique("stray").replace('-', "_");
        sqlx::query(
            "INSERT INTO metadata_change_log (entity_ref, logicalname, change_kind) \
             VALUES ($1, $2, 'upsert')",
        )
        .bind(Uuid::now_v7())
        .bind(&stray)
        .execute(&state.base.db)
        .await
        .expect("insert change-log row");

        let rec = recording(actor, Some(id), RecordingMode::Required);
        record(state, &rec, app_op("quick")).await;
        let row_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM changeset WHERE id = $1")
                .bind(id)
                .fetch_one(&state.base.db)
                .await
                .expect("row_version");

        let (status, closed) = send(
            &system.app,
            request(
                "POST",
                &format!("/api/v1/admin/changesets/{id}/close"),
                &cookie,
                Some(row_version),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{closed}");
        let warnings = closed["warnings"].as_array().expect("warnings");
        assert!(
            warnings
                .iter()
                .any(|w| w["kind"] == "unrecorded_entity_change" && w["entity"] == json!(stray)),
            "{closed}"
        );
        assert!(
            !warnings.iter().any(|w| w["entity"] == "contract"),
            "a recorded entity is covered: {closed}"
        );
    });
}

#[test]
fn an_automatic_changeset_is_sealed_on_first_read() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = &system.state;
        let (actor, cookie) = seed_admin(&state.base.db).await;

        // No open changeset and auto mode: the write gets its own closed,
        // unsealed automatic changeset.
        let rec = recording(actor, None, RecordingMode::Auto);
        record(state, &rec, app_op("auto")).await;
        let id: Uuid = sqlx::query_scalar(
            "SELECT id FROM changeset WHERE author_ref = $1 AND origin = 'auto'",
        )
        .bind(actor)
        .fetch_one(&state.base.db)
        .await
        .expect("the automatic changeset");

        let (status, detail) = send(
            &system.app,
            request(
                "GET",
                &format!("/api/v1/admin/changesets/{id}"),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["changeset"]["status"], "closed");
        let document = &detail["document"];
        assert_eq!(document["scope"], "auto");
        assert_eq!(
            document["checksum"].as_str(),
            Some(jcs::document_checksum(document).expect("checksum").as_str())
        );
        assert_eq!(detail["changeset"]["checksum"], document["checksum"]);

        // A second read seals nothing new.
        let (_, again) = send(
            &system.app,
            request(
                "GET",
                &format!("/api/v1/admin/changesets/{id}/export"),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(&again, document);
    });
}

#[test]
fn every_route_needs_system_admin() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let user = Uuid::now_v7();
        sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
            .bind(user)
            .bind(format!("changeset-plain-{user}"))
            .execute(&system.state.base.db)
            .await
            .expect("insert plain user");
        let cookie = session_cookie(user);
        let some = Uuid::now_v7();
        for (method, uri) in [
            ("GET", "/api/v1/admin/changesets".to_owned()),
            ("POST", "/api/v1/admin/changesets".to_owned()),
            ("GET", format!("/api/v1/admin/changesets/{some}")),
            ("POST", format!("/api/v1/admin/changesets/{some}/close")),
            ("POST", format!("/api/v1/admin/changesets/{some}/abandon")),
            ("GET", format!("/api/v1/admin/changesets/{some}/export")),
        ] {
            let body = (method == "POST").then(|| json!({}));
            let (status, _) =
                send(&system.app, request(method, &uri, &cookie, Some(0), body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
    });
}
