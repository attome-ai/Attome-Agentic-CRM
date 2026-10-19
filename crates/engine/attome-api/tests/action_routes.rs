//! Integration tests for `attome-ai`'s three mounted routes, through the
//! **full assembled middleware stack** — not `core_routes()` alone, which is
//! bare and would silently skip authentication.
//!
//! `attome-ai`'s own 35 unit tests cover the gate exhaustively. What they
//! cannot cover is everything between an HTTP request and that gate: the
//! extractor, the license gate at the router level, argument deserialisation,
//! and — the one that matters most — whether `record.get` really does inherit
//! the caller's record-level visibility rather than merely claiming to.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-api --test action_routes -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::sync::Arc;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_testkit::point_config_at;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// An admin, so record-level scoping is `Global` and the happy path is not
/// entangled with the access-ladder tests that already cover it elsewhere
/// (`record_level_security.rs` owns those, over the same predicate).
async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("action-routes-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin");

    // `SecurityContext::is_admin` is derived from holding `system.admin`
    // (`attome-security/src/resolver.rs:74`), not from a column — there is no
    // `is_admin` on `user_account`. Same seeding shape
    // `record_level_security.rs` uses.
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin must already be seeded by attome_security::seed::seed");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege \
            (id, user_ref, privilege_ref, is_active, created_at) \
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

fn test_config(ai_on: bool) -> AppConfig {
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
            {inference}
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        inference = if ai_on {
            r#""inference": { "ai": { "enabled": true, "fields": true, "chat": true, "semantic_search": true, "workflow_nodes": true } },"#
        } else {
            ""
        },
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// No `inference` section in the JSON above, so this is `InferenceSection::
/// default()` — every AI switch off and no model endpoint. That is the
/// **default state of every deployment**, and testing against it is
/// deliberate: it is what a fresh install actually does.
async fn test_system() -> Option<(EngineSystem, attome_db::DbPool)> {
    test_system_with(false).await
}

/// `ai_on = true` switches every AI surface on — needed only where the
/// behaviour under test sits behind the kill-switch (an agent write through
/// MCP). Everything else keeps the ships-dark default above.
async fn test_system_with(ai_on: bool) -> Option<(EngineSystem, attome_db::DbPool)> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config(ai_on);
    point_config_at(&mut config, &throwaway_url);
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

    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_ai::ActionModel)
        .build()
        .await
        .expect("build EngineSystem");

    // Fully licensed, so the route-level module gate is not what these tests
    // are measuring. `unlicensed_deployment_hides_the_whole_surface` below
    // flips it back off deliberately.
    //
    // Stored AFTER `build()`, as `s2s.rs` does: `build()` loads the
    // deployment's own licence into `state.modules`, so a licence stored
    // before it was overwritten with the degraded one and every AI route
    // answered 403 `feature_hidden`.
    let license = ModuleSet::from_bits([u64::MAX; 4]);
    system.state().modules.store(Arc::new(license));
    Some((system, db))
}

/// See `license_gating.rs`'s identical helper: an in-process `oneshot()` sends
/// neither a Sec-Fetch-Site nor an Origin, which `csrf_protect` correctly
/// rejects for a cookie-authenticated unsafe method. Stamping the header is
/// what a legitimate non-browser caller does, not a bypass of the check.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
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

async fn get(app: &axum::Router, path: &str, cookie: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn post(app: &axum::Router, path: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ── GET /api/v1/actions ──────────────────────────────────────────────────────

#[tokio::test]
async fn the_action_list_offers_core_reads_but_not_ai_actions_when_ai_is_off() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let (status, body) = get(&app, "/api/v1/actions", &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let ids: Vec<&str> = body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|i| i["id"].as_str().expect("id"))
        .collect();

    // This deployment has AI switched off (the default). `record.get` is
    // MODULE_CORE and must still be offered — an operator turning AI off must
    // not break structured reads that never touch a model.
    assert!(
        ids.contains(&"record.get"),
        "a core read must survive the AI kill-switch: {ids:?}"
    );
    assert!(
        !ids.contains(&"record.summarize"),
        "a MODULE_AI action must be absent while the kill-switch is off: {ids:?}"
    );
    // Not merely hidden from the list — actually uninvocable. The list and the
    // gate must agree, or a UI renders a button that 404s.
    let (status, _) = post(
        &app,
        "/api/v1/actions/record.summarize/invoke",
        &cookie,
        json!({ "args": { "entity": "user_account", "record_id": Uuid::now_v7() } }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a switched-off action must be invisible, not forbidden — a 403 would \
         confirm the feature exists"
    );
}

#[tokio::test]
async fn the_action_list_requires_authentication() {
    let (system, _db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/actions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── POST /api/v1/actions/{id}/invoke ─────────────────────────────────────────

#[tokio::test]
async fn record_get_returns_a_record_the_caller_can_see() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    // The caller's own systemuser row: a record that exists, is readable, and
    // needs no entity provisioning.
    let (status, body) = post(
        &app,
        "/api/v1/actions/record.get/invoke",
        &cookie,
        json!({ "args": { "entity": "user_account", "record_id": user_id } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "completed", "{body}");
    assert_eq!(
        body["result"]["id"].as_str(),
        Some(user_id.to_string().as_str()),
        "the action must return the record that was asked for: {body}"
    );
    assert!(
        body["provenance"].is_null(),
        "a structured read reaches no model and must carry no provenance: {body}"
    );
}

#[tokio::test]
async fn record_get_does_not_reveal_a_record_that_does_not_exist() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let (status, _) = post(
        &app,
        "/api/v1/actions/record.get/invoke",
        &cookie,
        json!({ "args": { "entity": "user_account", "record_id": Uuid::now_v7() } }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn query_execute_runs_a_stored_query_through_the_engines_own_path() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    // `user_account` has a seeded default view/query, so this exercises
    // the real lookup → privilege gate → scoping → bounded execution path
    // rather than a fixture query written to suit the test.
    let (status, body) = post(
        &app,
        "/api/v1/actions/query.execute/invoke",
        &cookie,
        json!({ "args": { "entity": "user_account", "page": 1, "page_size": 5 } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "completed", "{body}");
    assert!(
        body["result"]["data"]["records"].is_array(),
        "the action must return the engine's own tabular envelope: {body}"
    );
    assert!(
        body["result"]["data"]["records"]
            .as_array()
            .expect("records")
            .len()
            <= 5,
        "page_size must be honoured — the action must not bypass the \
         pagination contract: {body}"
    );
}

#[tokio::test]
async fn query_execute_cannot_be_handed_sql() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    // I-9: `ExecuteQueryRequest` has no field that carries SQL, so a supplied
    // one is an unknown field. Serde ignores unknown fields rather than
    // rejecting them, which means the assertion that matters is not "this
    // errors" but "this is INERT" — the SQL neither executes nor changes the
    // answer. Asserting the error would have been the weaker claim and would
    // break the day someone adds `deny_unknown_fields`.
    let baseline = post(
        &app,
        "/api/v1/actions/query.execute/invoke",
        &cookie,
        json!({ "args": { "entity": "user_account", "page_size": 5 } }),
    )
    .await;
    assert_eq!(baseline.0, StatusCode::OK, "{}", baseline.1);

    let with_sql = post(
        &app,
        "/api/v1/actions/query.execute/invoke",
        &cookie,
        json!({ "args": {
            "entity": "user_account",
            "page_size": 5,
            "sql": "SELECT 1",
            "sql_query": "DROP TABLE user_account",
            "base_sql": "SELECT * FROM privilege",
        }}),
    )
    .await;
    assert_eq!(with_sql.0, StatusCode::OK, "{}", with_sql.1);
    assert_eq!(
        with_sql.1["result"]["metadata"]["query_id"], baseline.1["result"]["metadata"]["query_id"],
        "a supplied SQL field must not change WHICH stored query ran"
    );
    assert_eq!(
        with_sql.1["result"]["data"]["columns"], baseline.1["result"]["data"]["columns"],
        "a supplied SQL field must not change the shape of the result — if it \
         did, model output would have reached the SQL parser (I-9)"
    );

    // And the table the injected DROP named is still there.
    let survives: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
          WHERE table_schema = current_schema() AND table_name = 'user_account')",
    )
    .fetch_one(&db)
    .await
    .expect("check the table still exists");
    assert!(survives, "the injected DROP must have been inert");

    // With no query selector at all, the action fails rather than guessing —
    // a supplied `sql` is not a selector and must not become one.
    let (status, _) = post(
        &app,
        "/api/v1/actions/query.execute/invoke",
        &cookie,
        json!({ "args": { "sql": "SELECT 1" } }),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "SQL alone must not select anything to run"
    );
}

#[tokio::test]
async fn an_unknown_action_is_indistinguishable_from_an_unavailable_one() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    // A model naming a tool that does not exist must not be able to learn
    // anything from the difference between "no such action" and "not licensed"
    // — both are 404 (I-9 / the dark license gate).
    for id in ["record.drop_table", "record.summarise"] {
        let (status, _) = post(
            &app,
            &format!("/api/v1/actions/{id}/invoke"),
            &cookie,
            json!({ "args": {} }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "unknown action {id} must 404, not 400/500"
        );
    }

    // A `..` segment never reaches the router: the web firewall (Z5-T4)
    // refuses it with 400 on every path, so the refusal says nothing about
    // which actions exist.
    let (status, body) = post(
        &app,
        "/api/v1/actions/../../etc/passwd/invoke",
        &cookie,
        json!({ "args": {} }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "request_rejected", "{body}");
}

#[tokio::test]
async fn malformed_arguments_are_rejected_before_anything_is_resolved() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    for args in [
        json!({}),                           // missing both
        json!({ "entity": "user_account" }), // missing record_id
        json!({ "entity": "user_account", "record_id": "not-a-uuid" }),
        json!({ "entity": 42, "record_id": Uuid::now_v7() }), // wrong type
    ] {
        let (status, _) = post(
            &app,
            "/api/v1/actions/record.get/invoke",
            &cookie,
            json!({ "args": args }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "malformed args {args} must be a validation failure"
        );
    }
}

#[tokio::test]
async fn invoking_requires_authentication() {
    let (system, _db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/actions/record.get/invoke")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "args": {} }).to_string()))
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── POST /api/v1/ai/suggestions/{id}/outcome ─────────────────────────────────

async fn seed_pending_suggestion(db: &attome_db::DbPool, user_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO ai_suggestion_outcome \
            (action_id, model_id, prompt_version, entity_logicalname, user_ref) \
         VALUES ('record.summarize', 'test-model', 'record.summarize/v1', \
                 'user_account', $1) \
         RETURNING id",
    )
    .bind(user_id)
    .fetch_one(db)
    .await
    .expect("seed a pending suggestion")
}

#[tokio::test]
async fn the_first_outcome_decision_wins() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, cookie) = seed_admin(&db).await;
    let suggestion_id = seed_pending_suggestion(&db, user_id).await;
    let app = full_app(system);

    let (status, body) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{suggestion_id}/outcome"),
        &cookie,
        json!({ "outcome": "accepted" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recorded"], true);

    // A double-submit must not overwrite an accept with a reject. The caller
    // is told theirs was not the decision that landed, rather than silently
    // corrupting the quality log.
    let (status, body) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{suggestion_id}/outcome"),
        &cookie,
        json!({ "outcome": "rejected" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["recorded"], false,
        "a second decision must not overwrite the first"
    );

    let (outcome, distance): (String, Option<i32>) =
        sqlx::query_as("SELECT outcome, edit_distance FROM ai_suggestion_outcome WHERE id = $1")
            .bind(suggestion_id)
            .fetch_one(&db)
            .await
            .expect("read back the outcome");
    assert_eq!(outcome, "accepted");
    assert_eq!(distance, None);
}

/// NEGATIVE: outcome data is the ground truth model comparisons read, so only
/// the human the suggestion was offered to may decide it. Another
/// authenticated user — even an admin — is told `recorded: false`, exactly
/// like a double-submit, and the row stays pending for its owner.
#[tokio::test]
async fn only_the_suggestions_owner_can_record_its_outcome() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (owner_id, owner_cookie) = seed_admin(&db).await;
    let (_, other_cookie) = seed_admin(&db).await;
    let suggestion_id = seed_pending_suggestion(&db, owner_id).await;
    let app = full_app(system);

    let (status, body) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{suggestion_id}/outcome"),
        &other_cookie,
        json!({ "outcome": "rejected" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recorded"], false, "someone else's suggestion: {body}");

    let outcome: String =
        sqlx::query_scalar("SELECT outcome FROM ai_suggestion_outcome WHERE id = $1")
            .bind(suggestion_id)
            .fetch_one(&db)
            .await
            .expect("read back");
    assert_eq!(outcome, "pending", "another user's decision must not land");

    let (_, body) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{suggestion_id}/outcome"),
        &owner_cookie,
        json!({ "outcome": "accepted" }),
    )
    .await;
    assert_eq!(body["recorded"], true, "the owner still decides it: {body}");
}

/// NEGATIVE: a suggestion with no recorded owner is decidable by nobody —
/// there is no `user_ref IS NULL` fallback that would let any caller write it.
#[tokio::test]
async fn an_unowned_suggestions_outcome_cannot_be_recorded_by_anyone() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let suggestion_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_suggestion_outcome \
            (action_id, model_id, prompt_version, entity_logicalname) \
         VALUES ('record.summarize', 'test-model', 'record.summarize/v1', 'user_account') \
         RETURNING id",
    )
    .fetch_one(&db)
    .await
    .expect("seed an unowned suggestion");
    let app = full_app(system);

    let (_, body) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{suggestion_id}/outcome"),
        &cookie,
        json!({ "outcome": "accepted" }),
    )
    .await;
    assert_eq!(body["recorded"], false, "{body}");
    let outcome: String =
        sqlx::query_scalar("SELECT outcome FROM ai_suggestion_outcome WHERE id = $1")
            .bind(suggestion_id)
            .fetch_one(&db)
            .await
            .expect("read back");
    assert_eq!(outcome, "pending");
}

// ── POST /api/v1/mcp — session binding and the allow-list ────────────────────

/// One JSON-RPC call, optionally naming a session.
async fn mcp(
    app: &axum::Router,
    cookie: &str,
    session: Option<Uuid>,
    method: &str,
    params: Value,
) -> Value {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/mcp")
        .header("cookie", cookie)
        .header("content-type", "application/json");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session.to_string());
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON-RPC body")
}

async fn mcp_initialize(app: &axum::Router, cookie: &str) -> Uuid {
    let body = mcp(app, cookie, None, "initialize", json!({})).await;
    body["result"]["sessionId"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("initialize must return a session id: {body}"))
}

/// A `tools/call`'s decoded payload, or `None` when the call was refused
/// before reaching a tool (a JSON-RPC error).
async fn mcp_tool_call(
    app: &axum::Router,
    cookie: &str,
    session: Uuid,
    tool: &str,
    arguments: Value,
) -> Option<(bool, Value)> {
    let body = mcp(
        app,
        cookie,
        Some(session),
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    )
    .await;
    let result = body.get("result")?;
    let is_error = result["isError"].as_bool().expect("isError");
    let text = result["content"][0]["text"].as_str().expect("text content");
    Some((is_error, serde_json::from_str(text).expect("JSON payload")))
}

// ── MCP entity admission (M3.4) fixtures ────────────────────────────────────
//
// MCP `record.*` tools are default-deny: an entity is reachable only once
// `ai.mcp_entity_admission` admits it, and security/identity/audit entities
// (`user_account` among them) never are. So the MCP tests below drive
// a throwaway business entity created through the admin API and admitted
// through the settings API — the same interfaces an operator uses.

async fn send_json(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A throwaway business entity, provisioned through the admin API.
async fn business_entity(app: &axum::Router, admin_cookie: &str) -> String {
    let name = format!("mcp_adm_{}", &Uuid::now_v7().simple().to_string()[20..]);
    let (status, body) = send_json(
        app,
        "POST",
        "/api/v1/admin/entities",
        admin_cookie,
        json!({ "logicalname": name, "name": "MCP admission test" }),
    )
    .await;
    assert!(status.is_success(), "create entity: {status} {body}");
    let entity_id = body["id"]
        .as_str()
        .unwrap_or_else(|| panic!("a created entity carries its id: {body}"));
    // One plain text field, so a record has something to carry — the
    // generic create refuses a record with no recognised fields.
    let (status, body) = send_json(
        app,
        "POST",
        &format!("/api/v1/admin/entities/{entity_id}/fields"),
        admin_cookie,
        json!({ "logicalname": "label", "name": "Label", "field_type": "text" }),
    )
    .await;
    assert!(status.is_success(), "create field: {status} {body}");
    name
}

/// One record of `entity`, created through the generic entity API.
async fn business_record(app: &axum::Router, admin_cookie: &str, entity: &str) -> Uuid {
    let (status, body) = send_json(
        app,
        "POST",
        &format!("/api/v1/{entity}"),
        admin_cookie,
        json!({ "label": "mcp admission" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create record: {body}");
    body["id"]
        .as_str()
        .or_else(|| body["data"]["id"].as_str())
        .and_then(|id| Uuid::parse_str(id).ok())
        .unwrap_or_else(|| panic!("a created record carries its id: {body}"))
}

/// Admits `entity` for `verbs` over MCP, through `PUT /api/v1/admin/settings`.
/// Read-modify-write, so entities admitted by an earlier call stay admitted.
async fn admit_over_mcp(app: &axum::Router, admin_cookie: &str, entity: &str, verbs: &[&str]) {
    let (status, listed) = get(app, "/api/v1/admin/settings", admin_cookie).await;
    assert_eq!(status, StatusCode::OK, "list settings: {listed}");
    let mut value = listed["items"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["key"] == "ai.mcp_entity_admission")
        })
        .and_then(|item| item["value"].as_object().cloned())
        .unwrap_or_default();
    value.insert(entity.to_owned(), json!(verbs));
    let (status, body) = send_json(
        app,
        "PUT",
        "/api/v1/admin/settings/ai.mcp_entity_admission",
        admin_cookie,
        json!({ "scope": "deployment", "value": value }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admit {entity}: {body}");
}

/// A business entity with one record, admitted over MCP for `verbs`.
async fn admitted_record(app: &axum::Router, admin_cookie: &str, verbs: &[&str]) -> (String, Uuid) {
    let entity = business_entity(app, admin_cookie).await;
    let record = business_record(app, admin_cookie, &entity).await;
    admit_over_mcp(app, admin_cookie, &entity, verbs).await;
    (entity, record)
}

/// NEGATIVE: an MCP session id is a handle, not a credential. The owner can
/// use it; another authenticated user presenting the same id is refused at
/// both `tools/list` and `tools/call`, before any tool runs.
#[tokio::test]
async fn an_mcp_session_is_usable_only_by_the_user_who_opened_it() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, owner_cookie) = seed_admin(&db).await;
    let (_, other_cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let (entity, record) = admitted_record(&app, &owner_cookie, &["read"]).await;
    let session = mcp_initialize(&app, &owner_cookie).await;
    let args = json!({ "entity": entity, "record_id": record });

    let (is_error, payload) =
        mcp_tool_call(&app, &owner_cookie, session, "record.get", args.clone())
            .await
            .expect("the owner's call reaches the tool");
    assert!(!is_error, "{payload}");

    assert!(
        mcp_tool_call(&app, &other_cookie, session, "record.get", args)
            .await
            .is_none(),
        "another user must not be able to call a tool through someone else's session"
    );
    let listed = mcp(&app, &other_cookie, Some(session), "tools/list", json!({})).await;
    assert!(
        listed.get("error").is_some() && listed.get("result").is_none(),
        "another user must not be able to list tools through someone else's session: {listed}"
    );
}

/// **NEGATIVE, the consequence.** A webchat conversation's session starts
/// untainted; every MCP session starts tainted. Borrowing the untainted one
/// used to let an agent write auto-execute where the caller's own MCP session
/// demands confirmation. Control: the caller's own session returns
/// `confirmation_required`. Borrowed — by another user, or by the webchat
/// session's own owner across surfaces — the call is refused and nothing is
/// written.
#[tokio::test]
async fn a_borrowed_untainted_session_cannot_be_used_to_skip_confirmation() {
    let (system, db) = skip_if_no_db!(test_system_with(true).await);
    let (webchat_owner, webchat_owner_cookie) = seed_admin(&db).await;
    let (_, borrower_cookie) = seed_admin(&db).await;
    let webchat_session: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface, tainted) \
         VALUES ($1, 2, 'webchat', false) RETURNING id",
    )
    .bind(webchat_owner)
    .fetch_one(&db)
    .await
    .expect("open an untainted webchat session");
    let app = full_app(system);

    let marker = format!("borrowed-session-probe-{}", Uuid::now_v7());
    let remember = json!({ "scope_kind": "user", "kind": "note", "summary": marker });

    let own_session = mcp_initialize(&app, &borrower_cookie).await;
    // Control: the caller's own session offers the tool. Listing first also
    // refreshes the process-global runtime AI switch before the first
    // dispatch; without it this test (the first in the suite) failed twice
    // in full runs with a dark refusal while passing alone — consistent with
    // a cold first read of the switch failing closed. Not an admission
    // effect: `memory.remember` is not an MCP-admission-governed tool.
    let listed = mcp(
        &app,
        &borrower_cookie,
        Some(own_session),
        "tools/list",
        json!({}),
    )
    .await;
    let offered = listed["result"]["tools"]
        .as_array()
        .is_some_and(|tools| tools.iter().any(|t| t["name"] == "memory.remember"));
    assert!(
        offered,
        "control: the own session offers memory.remember: {listed}"
    );
    let (_, payload) = mcp_tool_call(
        &app,
        &borrower_cookie,
        own_session,
        "memory.remember",
        remember.clone(),
    )
    .await
    .expect("the caller's own session reaches the gate");
    assert_eq!(
        payload["status"], "confirmation_required",
        "control: an MCP session is tainted, so an agent write needs confirmation: {payload}"
    );

    for cookie in [&borrower_cookie, &webchat_owner_cookie] {
        assert!(
            mcp_tool_call(
                &app,
                cookie,
                webchat_session,
                "memory.remember",
                remember.clone()
            )
            .await
            .is_none(),
            "a webchat session must not be usable over MCP"
        );
    }

    let written: i64 = sqlx::query_scalar("SELECT count(*) FROM memory WHERE summary = $1")
        .bind(&marker)
        .fetch_one(&db)
        .await
        .expect("count memories");
    assert_eq!(
        written, 0,
        "nothing may have been written through a borrowed session"
    );
}

/// NEGATIVE: a session's allow-list is enforced when a tool is called, not
/// only when tools are listed. Calling a hidden tool by name is refused, and
/// is indistinguishable from calling one that does not exist.
#[tokio::test]
async fn the_session_allow_list_is_enforced_when_a_tool_is_called() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let (entity, record) = admitted_record(&app, &cookie, &["read"]).await;
    let session = mcp_initialize(&app, &cookie).await;
    let args = json!({ "entity": entity, "record_id": record });

    let (is_error, payload) = mcp_tool_call(&app, &cookie, session, "record.get", args.clone())
        .await
        .expect("reaches the tool");
    assert!(!is_error, "control: unrestricted session: {payload}");

    sqlx::query(
        "UPDATE agent_session SET allowed_action_ids = ARRAY['query.execute'] WHERE id = $1",
    )
    .bind(session)
    .execute(&db)
    .await
    .expect("narrow the session's allow-list");

    let listed = mcp(&app, &cookie, Some(session), "tools/list", json!({})).await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(!names.contains(&"record.get"), "{names:?}");

    let (is_error, payload) = mcp_tool_call(&app, &cookie, session, "record.get", args)
        .await
        .expect("a refusal is a tool result");
    assert!(
        is_error,
        "a tool outside the allow-list must be refused: {payload}"
    );
    assert_eq!(payload["error"], "unknown or unavailable", "{payload}");
}

#[tokio::test]
async fn an_edit_requires_a_distance_and_a_non_edit_forbids_one() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    // Migration 0118's CHECK ties `outcome = 'edited'` to a non-NULL
    // edit_distance in BOTH directions. If the route let either half through,
    // the write would fail at the database with a 23514 → bare 500.
    let id = seed_pending_suggestion(&db, user_id).await;
    let (status, _) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{id}/outcome"),
        &cookie,
        json!({ "outcome": "edited" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{id}/outcome"),
        &cookie,
        json!({ "outcome": "accepted", "edit_distance": 4 }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{id}/outcome"),
        &cookie,
        json!({ "outcome": "abandoned" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // The valid edit still lands, proving the rejections above were about the
    // shape and not a route that rejects everything.
    let (status, body) = post(
        &app,
        &format!("/api/v1/ai/suggestions/{id}/outcome"),
        &cookie,
        json!({ "outcome": "edited", "edit_distance": 4 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recorded"], true);

    let (outcome, distance): (String, Option<i32>) =
        sqlx::query_as("SELECT outcome, edit_distance FROM ai_suggestion_outcome WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("read back the outcome");
    assert_eq!(outcome, "edited");
    assert_eq!(distance, Some(4));
}

// ── The license gate at the router level ─────────────────────────────────────

#[tokio::test]
async fn an_unlicensed_deployment_hides_the_whole_surface() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    // Degraded: no module bits at all, including MODULE_AI, which is what
    // `ActionModel` mounts under.
    system
        .state()
        .modules
        .store(Arc::new(ModuleSet::core_only()));
    let app = full_app(system);

    let (status, _) = get(&app, "/api/v1/actions", &cookie).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an unlicensed deployment must not serve the action surface"
    );
}

// ── POST /api/v1/mcp — characterization before the protocol migration ────────
//
// MCP plan item M0.2 (`document/xrm/pending_full_plan/mcp-excellence-10-10.md`).
// These pin what the surface does today, on the legacy revision it speaks
// (`2025-06-18`), so the move to the current revision (M1) changes only what it
// means to change. A test here that has to change must change in the same diff
// as the behaviour, with the contract row it serves named in that diff.

/// One raw POST to the MCP endpoint, with no status assertion: optional cookie
/// and session, any body. For the envelope cases the `mcp` helper rejects.
async fn mcp_raw(
    app: &axum::Router,
    cookie: Option<&str>,
    session: Option<Uuid>,
    body: Value,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    mcp_raw_with_origin(app, cookie, session, None, body).await
}

/// `mcp_raw`, plus an `Origin` header — M1.6's case. Separate rather than a
/// fifth parameter on `mcp_raw` so the calls that do not care about `Origin`
/// stay as they are.
async fn mcp_raw_with_origin(
    app: &axum::Router,
    cookie: Option<&str>,
    session: Option<Uuid>,
    origin: Option<&str>,
    body: Value,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/mcp")
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(session) = session {
        request = request.header("mcp-session-id", session.to_string());
    }
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (status, headers, bytes.to_vec())
}

/// A **modern** request: `_meta` carries the protocol version, and the mirrored
/// headers repeat the version, the method and (when present) `params.name`.
///
/// Every part is overridable, because half of M1.2's cases exist to make one of
/// them disagree with the body. `version_header` of `None` omits the header
/// entirely, which is its own failure mode.
#[allow(clippy::too_many_arguments)]
async fn mcp_modern(
    app: &axum::Router,
    cookie: &str,
    session: Option<Uuid>,
    method: &str,
    params: Value,
    declared_version: &str,
    version_header: Option<&str>,
    method_header: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": declared_version,
        "io.modelcontextprotocol/clientInfo": { "name": "test-host", "version": "1.0.0" },
        "io.modelcontextprotocol/clientCapabilities": {},
    });

    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/mcp")
        .header("content-type", "application/json")
        .header("cookie", cookie);
    if let Some(session) = session {
        request = request.header("mcp-session-id", session.to_string());
    }
    if let Some(version) = version_header {
        request = request.header("mcp-protocol-version", version);
    }
    request = request.header("mcp-method", method_header.unwrap_or(method));
    if let Some(name) = params.get("name").and_then(Value::as_str) {
        request = request.header("mcp-name", name);
    }

    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// One request with a bare HTTP method and no body — for the 405 cases.
async fn mcp_bare_method(app: &axum::Router, method: &str, cookie: &str) -> StatusCode {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri("/api/v1/mcp")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    response.status()
}

/// **M1.2 / finding F-5.** The endpoint serves both eras. A request declaring
/// `_meta`'s protocol version is modern: it answers `server/discover`, stamps
/// `resultType`, and enforces the transport's header rules. A request that
/// declares nothing is legacy and is served exactly as it always was — which is
/// what lets the modern era arrive without breaking an existing host.
#[tokio::test]
async fn the_mcp_endpoint_serves_the_modern_era_beside_the_legacy_one() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    const MODERN: &str = "2026-07-28";

    // Discovery: both revisions offered, so a client can choose one.
    let (status, body) = mcp_modern(
        &app,
        &cookie,
        None,
        "server/discover",
        json!({}),
        MODERN,
        Some(MODERN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let versions = body["result"]["supportedVersions"]
        .as_array()
        .unwrap_or_else(|| panic!("supportedVersions: {body}"));
    assert!(versions.iter().any(|v| v == MODERN), "{body}");
    assert!(versions.iter().any(|v| v == "2025-06-18"), "{body}");
    assert_eq!(body["result"]["resultType"], "complete", "{body}");
    assert!(
        body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "attome-xrm",
        "{body}"
    );

    // An ordinary modern call carries resultType too.
    let (status, body) = mcp_modern(
        &app,
        &cookie,
        None,
        "ping",
        json!({}),
        MODERN,
        Some(MODERN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["resultType"], "complete", "{body}");

    // The legacy era is untouched: no _meta, no mirrored headers, no
    // resultType, and still 200.
    let legacy = mcp(&app, &cookie, None, "ping", json!({})).await;
    assert_eq!(legacy["result"], json!({}), "{legacy}");
}

/// **M1.2, the transport's refusals.** A header that disagrees with the body is
/// `-32020`; a version this server does not implement is `-32022` and says what
/// it does implement. Both are 400, because the request never reached the
/// protocol layer.
#[tokio::test]
async fn a_modern_mcp_request_with_a_bad_envelope_is_refused_at_the_transport() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    const MODERN: &str = "2026-07-28";

    // Header disagrees with the body. An intermediary routing on the header
    // while this server executes on the body is the split-brain these rules
    // exist to prevent.
    let (status, body) = mcp_modern(
        &app,
        &cookie,
        None,
        "ping",
        json!({}),
        MODERN,
        Some("2025-11-25"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32020, "{body}");

    // Version header missing entirely.
    let (status, body) =
        mcp_modern(&app, &cookie, None, "ping", json!({}), MODERN, None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32020, "{body}");

    // Method header disagrees with the body's method.
    let (status, body) = mcp_modern(
        &app,
        &cookie,
        None,
        "ping",
        json!({}),
        MODERN,
        Some(MODERN),
        Some("tools/list"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32020, "{body}");

    // A revision we do not implement, answered with the ones we do.
    let (status, body) = mcp_modern(
        &app,
        &cookie,
        None,
        "ping",
        json!({}),
        "1900-01-01",
        Some("1900-01-01"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32022, "{body}");
    assert!(
        body["error"]["data"]["supported"]
            .as_array()
            .is_some_and(|v| v.iter().any(|x| x == "2026-07-28")),
        "the refusal must name what this server does implement: {body}"
    );
}

/// **M1.2, method handling.** An unimplemented method is 404 for a modern
/// client — "this server does not do that", distinguishable from "this path is
/// not an MCP endpoint" — while a legacy client still gets 200, which is what
/// its revision expects. A wrong HTTP method is 405.
#[tokio::test]
async fn an_unimplemented_mcp_method_is_404_for_modern_and_200_for_legacy() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    const MODERN: &str = "2026-07-28";

    let (status, body) = mcp_modern(
        &app,
        &cookie,
        None,
        "resources/list",
        json!({}),
        MODERN,
        Some(MODERN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], -32601, "{body}");

    let legacy = mcp(&app, &cookie, None, "resources/list", json!({})).await;
    assert_eq!(legacy["error"]["code"], -32601, "{legacy}");

    assert_eq!(
        mcp_bare_method(&app, "GET", &cookie).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "the modern transport removed the GET stream"
    );
    assert_eq!(
        mcp_bare_method(&app, "DELETE", &cookie).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "session termination by DELETE belongs to the revision that had sessions"
    );
}

/// **M1.6 / finding F-7.** A request carrying a disallowed `Origin` is refused
/// with 403 before it reaches the protocol layer, whatever credential it
/// presents.
///
/// The control matters more than the refusal here: `full_app` stamps
/// `sec-fetch-site: same-origin` on every request, which is exactly what makes
/// `csrf_protect` *allow* this call. So the 403 below cannot be CSRF doing the
/// work — it is the endpoint's own check, which is the point of F-7: CSRF only
/// covers cookie-authenticated mutating requests, leaving API-key and bearer
/// callers unprotected against a hostile page.
///
/// An absent `Origin` stays allowed: the ordinary MCP host is not a browser and
/// sends none, and the transport conditions its refusal on the header being
/// present.
#[tokio::test]
async fn an_mcp_request_from_a_disallowed_origin_is_refused_before_the_protocol_layer() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {} });

    let (status, _, _) = mcp_raw_with_origin(
        &app,
        Some(&cookie),
        None,
        Some("https://evil.example"),
        ping.clone(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a hostile Origin must be refused even though Sec-Fetch-Site satisfies CSRF"
    );

    // The configured allow-list is `http://{frontend_host}:{frontend_port}`,
    // and this suite's config names localhost:4200.
    let (status, _, _) = mcp_raw_with_origin(
        &app,
        Some(&cookie),
        None,
        Some("http://localhost:4200"),
        ping.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an allow-listed Origin is served");

    let (status, _, _) = mcp_raw(&app, Some(&cookie), None, ping).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a non-browser host sends no Origin and must still be served"
    );
}

/// `initialize` answers with the pinned revision, advertises `tools` only, and
/// opens a session that is the caller's own, on surface `mcp`, tainted, at the
/// `Consequential` ceiling (D-485).
///
/// **F-1, closed by M1.5.** The legacy transport hands a host its session in
/// the `Mcp-Session-Id` response header, and a standard host reads it there and
/// nowhere else — so while the id travelled only in the result body, no
/// conforming client could hold a session at all. Header and body must agree:
/// a host trusting either one alone would otherwise address a different
/// session.
#[tokio::test]
async fn mcp_initialize_opens_a_tainted_consequential_session_for_the_caller() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let (status, headers, bytes) = mcp_raw(
        &app,
        Some(&cookie),
        None,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&bytes).expect("JSON-RPC body");
    let result = &body["result"];
    assert_eq!(result["protocolVersion"], "2025-06-18", "{body}");
    assert_eq!(
        result["capabilities"],
        json!({ "tools": { "listChanged": false } }),
        "{body}"
    );
    assert_eq!(result["serverInfo"]["name"], "attome-xrm", "{body}");
    let session = result["sessionId"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("initialize must return a session id: {body}"));
    // F-1, closed by M1.5: the legacy transport hands a host its session in the
    // response header. A standard host reads it there and nowhere else, so
    // before this the surface was unusable by a conforming client. The body
    // keeps carrying the same id, and the two must agree — a host that trusted
    // either one alone would otherwise talk to a different session.
    assert_eq!(
        headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok()),
        Some(session.to_string().as_str()),
        "initialize must return the session id in the Mcp-Session-Id header, \
         matching the body"
    );

    let (owner, surface, tainted, ceiling): (Uuid, String, bool, i16) = sqlx::query_as(
        "SELECT owner_user_id, surface, tainted, risk_ceiling \
         FROM agent_session WHERE id = $1",
    )
    .bind(session)
    .fetch_one(&db)
    .await
    .expect("read the session row");
    assert_eq!(owner, user_id);
    assert_eq!(surface, "mcp");
    assert!(tainted, "every MCP session starts tainted");
    assert_eq!(
        ceiling, 2,
        "2 is Consequential (session.rs risk_tier_to_i16)"
    );
}

/// The JSON-RPC envelope: `ping`, an unimplemented method, a notification, a
/// call that names no session, and no credentials at all.
#[tokio::test]
async fn mcp_envelope_answers_ping_notifications_unknown_methods_and_missing_sessions() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let ping = mcp(&app, &cookie, None, "ping", json!({})).await;
    assert_eq!(ping["result"], json!({}), "{ping}");

    let unknown = mcp(&app, &cookie, None, "resources/list", json!({})).await;
    assert_eq!(unknown["error"]["code"], -32601, "{unknown}");

    let (status, _, bytes) = mcp_raw(
        &app,
        Some(&cookie),
        None,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(bytes.is_empty(), "a notification has no response body");

    let missing = mcp(&app, &cookie, None, "tools/list", json!({})).await;
    assert_eq!(missing["error"]["code"], -32602, "{missing}");
    assert!(
        missing["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("initialize"),
        "the refusal names the fix: {missing}"
    );

    let (status, _, _) = mcp_raw(
        &app,
        None,
        None,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// `tools/list` offers action ids unchanged, each with an object input schema
/// and a description, in the same order on every call.
#[tokio::test]
async fn mcp_tools_list_offers_action_ids_with_object_schemas_in_a_stable_order() {
    let (system, db) = skip_if_no_db!(test_system_with(true).await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let session = mcp_initialize(&app, &cookie).await;

    let first = mcp(&app, &cookie, Some(session), "tools/list", json!({})).await;
    let tools = first["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools: {first}"));
    assert!(!tools.is_empty(), "{first}");
    let registry = attome_ai::registry::ActionRegistry::new();
    for tool in tools {
        let name = tool["name"].as_str().expect("name");
        // N12-T2: the search tool is the one listed tool that is not an action.
        assert!(
            name == attome_ai::mcp::SEARCH_TOOL || registry.resolve(name).is_some(),
            "{name} must be an action id, unchanged"
        );
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert!(
            !tool["description"].as_str().unwrap_or_default().is_empty(),
            "{tool}"
        );
    }
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"record.get"), "{names:?}");

    let second = mcp(&app, &cookie, Some(session), "tools/list", json!({})).await;
    let again: Vec<&str> = second["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, again, "the tool list is deterministic across calls");

    // M1.7 / finding F-9. `cacheScope` must be `private`: the list is filtered
    // by the caller's licence, privileges and session allow-list, so a shared
    // cache holding one caller's list under a public scope would hand it to the
    // next caller.
    assert_eq!(first["result"]["cacheScope"], "private", "{first}");
    assert!(
        first["result"]["ttlMs"].as_u64().is_some_and(|ms| ms > 0),
        "a freshness hint must be present: {first}"
    );
}

/// A completed call is JSON wrapped in one text block, with no structured
/// content. An unknown tool is a tool result with `isError`, carrying the same
/// masked message as a hidden one (D-010), not a JSON-RPC protocol error.
#[tokio::test]
async fn mcp_tool_results_are_text_wrapped_json_and_unknown_tools_are_refused_darkly() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let (entity, record) = admitted_record(&app, &cookie, &["read"]).await;
    let session = mcp_initialize(&app, &cookie).await;

    let body = mcp(
        &app,
        &cookie,
        Some(session),
        "tools/call",
        json!({
            "name": "record.get",
            "arguments": { "entity": entity, "record_id": record },
        }),
    )
    .await;
    let result = &body["result"];
    assert_eq!(result["isError"], false, "{body}");
    assert_eq!(result["content"][0]["type"], "text", "{body}");
    assert!(result.get("structuredContent").is_none(), "{body}");
    let payload: Value = serde_json::from_str(result["content"][0]["text"].as_str().expect("text"))
        .expect("the text block is JSON");
    assert!(payload.get("result").is_some(), "{payload}");

    let (is_error, refused) = mcp_tool_call(&app, &cookie, session, "nothing.here", json!({}))
        .await
        .expect("an unknown tool is a tool result, not a protocol error");
    assert!(is_error, "{refused}");
    assert_eq!(refused["error"], "unknown or unavailable", "{refused}");
}

/// **Four-eyes across the boundary.** A `Consequential` tool called over MCP
/// raises an approval and runs nothing. An identical retry returns the same
/// approval rather than raising a second one (D-502).
#[tokio::test]
async fn a_consequential_mcp_call_raises_one_approval_and_executes_nothing() {
    let (system, db) = skip_if_no_db!(test_system_with(true).await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let session = mcp_initialize(&app, &cookie).await;
    let target = mcp_initialize(&app, &cookie).await;
    let args = json!({ "session_id": target });

    let (is_error, first) = mcp_tool_call(&app, &cookie, session, "agent.pause", args.clone())
        .await
        .expect("reaches the gate");
    assert!(!is_error, "{first}");
    assert_eq!(first["status"], "approval_required", "{first}");
    let approval_id = first["approval_id"]
        .as_str()
        .unwrap_or_else(|| panic!("an approval id: {first}"))
        .to_owned();

    let (_, retry) = mcp_tool_call(&app, &cookie, session, "agent.pause", args)
        .await
        .expect("reaches the gate");
    assert_eq!(retry["status"], "approval_required", "{retry}");
    assert_eq!(
        retry["approval_id"],
        approval_id.as_str(),
        "an identical retry returns the same approval, never a second one"
    );

    let paused: bool =
        sqlx::query_scalar("SELECT paused_at IS NOT NULL FROM agent_session WHERE id = $1")
            .bind(target)
            .fetch_one(&db)
            .await
            .expect("read the target session");
    assert!(!paused, "nothing may execute before a human approves");
}

/// A paused session is refused until it is resumed, and a revoked one is
/// refused for good. Neither refusal opens a replacement session: the kill
/// switch stays a kill switch (D-460).
#[tokio::test]
async fn a_paused_or_revoked_mcp_session_is_refused_and_never_silently_replaced() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let (entity, record) = admitted_record(&app, &cookie, &["read"]).await;
    let session = mcp_initialize(&app, &cookie).await;
    let args = json!({ "entity": entity, "record_id": record });

    sqlx::query(
        "UPDATE agent_session \
         SET paused_at = NOW(), paused_by = $2, paused_reason = 'm0 characterization' \
         WHERE id = $1",
    )
    .bind(session)
    .bind(user_id)
    .execute(&db)
    .await
    .expect("pause the session");
    let refused = mcp(
        &app,
        &cookie,
        Some(session),
        "tools/call",
        json!({ "name": "record.get", "arguments": args.clone() }),
    )
    .await;
    assert!(
        refused.get("result").is_none(),
        "a paused session must not reach a tool: {refused}"
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no longer live"),
        "{refused}"
    );

    sqlx::query(
        "UPDATE agent_session \
         SET paused_at = NULL, paused_by = NULL, paused_reason = NULL WHERE id = $1",
    )
    .bind(session)
    .execute(&db)
    .await
    .expect("resume the session");
    let (is_error, payload) = mcp_tool_call(&app, &cookie, session, "record.get", args)
        .await
        .expect("a resumed session reaches the tool");
    assert!(!is_error, "{payload}");

    sqlx::query(
        "UPDATE agent_session \
         SET revoked_at = NOW(), revoked_by = $2, revoked_reason = 'm0 characterization' \
         WHERE id = $1",
    )
    .bind(session)
    .bind(user_id)
    .execute(&db)
    .await
    .expect("revoke the session");
    let listed = mcp(&app, &cookie, Some(session), "tools/list", json!({})).await;
    assert!(
        listed.get("result").is_none(),
        "a revoked session must not list tools: {listed}"
    );

    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_session \
         WHERE owner_user_id = $1 AND surface = 'mcp'",
    )
    .bind(user_id)
    .fetch_one(&db)
    .await
    .expect("count the caller's MCP sessions");
    assert_eq!(
        sessions, 1,
        "a refused call must never open a replacement session"
    );
}

/// **C5: MCP gains the business writes and none of them bypasses the gate.**
/// The C5 writes are ordinary catalogue actions, so `tools/call` reaches them
/// through the same `dispatch` → `gate::evaluate` as chat. MCP has no
/// confirmation model of its own; it relays the gate's decision.
///
/// The session is **untainted** on purpose (MCP sessions start tainted; the
/// flag is cleared with test-only SQL, as `memory_lifecycle.rs` does): so the
/// `confirmation_required` for `record.create` is `agent_must_confirm`'s,
/// not taint's. `record.delete` is `Consequential` and becomes an approval
/// request. Nothing is written by either.
#[tokio::test]
async fn mcp_business_writes_confirm_or_await_approval_and_write_nothing() {
    let (system, db) = skip_if_no_db!(test_system_with(true).await);
    let (_, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let (entity, target) = admitted_record(&app, &cookie, &["create", "delete"]).await;
    let session = mcp_initialize(&app, &cookie).await;
    sqlx::query("UPDATE agent_session SET tainted = false WHERE id = $1")
        .bind(session)
        .execute(&db)
        .await
        .expect("clear the session's taint");
    let table = attome_core::quote_ident(&entity);
    let rows = |db: attome_db::DbPool, table: String| async move {
        sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&db)
            .await
            .expect("count")
    };

    let (is_error, created) = mcp_tool_call(
        &app,
        &cookie,
        session,
        "record.create",
        json!({ "entity": entity, "values": { "label": "via mcp" } }),
    )
    .await
    .expect("record.create reaches the gate");
    assert!(!is_error, "{created}");
    assert_eq!(
        created["status"], "confirmation_required",
        "an untainted MCP agent's create still needs a human: {created}"
    );
    assert_eq!(rows(db.clone(), table.clone()).await, 1, "nothing created");

    let (is_error, deleted) = mcp_tool_call(
        &app,
        &cookie,
        session,
        "record.delete",
        json!({ "entity": entity, "record_id": target }),
    )
    .await
    .expect("record.delete reaches the gate");
    assert!(!is_error, "{deleted}");
    assert_eq!(deleted["status"], "approval_required", "{deleted}");
    let still_active: bool = sqlx::query_scalar(&format!(
        "SELECT COALESCE(is_active, true) FROM {table} WHERE id = $1"
    ))
    .bind(target)
    .fetch_one(&db)
    .await
    .expect("read target");
    assert!(still_active, "nothing deleted before an approval");
}

/// **NEGATIVE, M3.4 default-deny through the route.** An entity nobody
/// admitted is refused darkly — the same masked message as an unknown tool —
/// for a read and for a write, and the write raises no confirmation or
/// approval. An admitted verb on the same entity is the control; a
/// security entity stays refused even when the setting lists it.
#[tokio::test]
async fn an_unadmitted_entity_is_refused_darkly_over_mcp() {
    let (system, db) = skip_if_no_db!(test_system_with(true).await);
    let (user_id, cookie) = seed_admin(&db).await;
    let app = full_app(system);
    let entity = business_entity(&app, &cookie).await;
    let record = business_record(&app, &cookie, &entity).await;
    let session = mcp_initialize(&app, &cookie).await;
    let get_args = json!({ "entity": entity, "record_id": record });

    for (tool, args) in [
        ("record.get", get_args.clone()),
        ("record.delete", get_args.clone()),
        (
            "record.create",
            json!({ "entity": entity, "values": { "label": "via mcp" } }),
        ),
    ] {
        let (is_error, payload) = mcp_tool_call(&app, &cookie, session, tool, args)
            .await
            .expect("a refusal is a tool result");
        assert!(is_error, "{tool} on an unadmitted entity: {payload}");
        assert_eq!(
            payload["error"], "unknown or unavailable",
            "{tool}: {payload}"
        );
    }

    admit_over_mcp(&app, &cookie, &entity, &["read"]).await;
    let (is_error, payload) = mcp_tool_call(&app, &cookie, session, "record.get", get_args)
        .await
        .expect("reaches the tool");
    assert!(!is_error, "control: an admitted read works: {payload}");

    admit_over_mcp(&app, &cookie, "user_account", &["read"]).await;
    let (is_error, payload) = mcp_tool_call(
        &app,
        &cookie,
        session,
        "record.get",
        json!({ "entity": "user_account", "record_id": user_id }),
    )
    .await
    .expect("a refusal is a tool result");
    assert!(is_error, "a security entity is never admitted: {payload}");
    assert_eq!(payload["error"], "unknown or unavailable", "{payload}");
}

/// K1-T3: a record under an active legal hold cannot be deleted, not even
/// into the recycle bin; once the hold is released it can.
#[tokio::test]
async fn a_record_under_a_legal_hold_cannot_be_deleted() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let (status, created) = post(
        &app,
        "/api/v1/note",
        &cookie,
        json!({ "title": "held", "note_text": "kept for a matter",
                "entity_name": "user_account", "record_id": user_id.to_string() }),
    )
    .await;
    assert!(status.is_success(), "{created}");
    let note_id: Uuid = created["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("note id");

    let hold_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ('note', $1, 'k1-t3-matter', $2) RETURNING id",
    )
    .bind(note_id)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .expect("place a hold");

    let delete = |app: axum::Router| async move {
        app.oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/note/{note_id}"))
                .header("cookie", cookie_for_delete(user_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("delete")
        .status()
    };
    assert_eq!(delete(app.clone()).await, StatusCode::CONFLICT);

    sqlx::query("UPDATE legal_hold SET released_at = now() WHERE id = $1")
        .bind(hold_id)
        .execute(&db)
        .await
        .expect("release the hold");
    assert!(delete(app).await.is_success());
}

fn cookie_for_delete(user_id: Uuid) -> String {
    session_cookie(user_id)
}
