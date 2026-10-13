//! D-602 (basic-units plan U4 + U5): record reminders and per-user
//! notification preferences, through the real middleware stack.
//!
//! - `GET/PUT /api/v1/me/notification-preferences` is the caller's own and
//!   nobody else's; a stale `row_version` is a 409; a mandatory template
//!   cannot be muted.
//! - `reminder`: a non-admin can only set a reminder for themselves
//!   (`entity_mutation::SELF_ADDRESSED_ENTITIES`), delivery is exactly-once
//!   across two concurrent sweeps, and a reminder whose record the recipient
//!   can no longer read is dismissed, not delivered.
//!
//! Requires a live Postgres (`DATABASE_URL`, migrations through 0497) and
//! Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`):
//!
//! ```powershell
//! cargo test -p attome-api --test reminders_preferences -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::reminder_access::EngineReminderAccess;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_notification::reminders::{
    REASON_RECORD_NOT_VISIBLE, ReminderRecordAccess, run_due_reminders,
};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const PREFS: &str = "/api/v1/me/notification-preferences";

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
                "connection_number": 8, "timeout": 5.0
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
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
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
    let system = EngineSystem::builder(EngineState::new(base))
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

async fn seed_user(db: &PgPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("d602-user-{user_id}"))
    .bind(attome_testkit::unique_email("d602"))
    .execute(db)
    .await
    .expect("insert throwaway user");
    user_id
}

async fn seed_admin(db: &PgPool) -> (Uuid, String) {
    let user_id = seed_user(db).await;
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant system.admin");
    (user_id, session_cookie(user_id))
}

/// A role granting `"{entity}.{action}"` for every pair, assigned to `user`.
async fn grant(db: &PgPool, user_id: Uuid, grants: &[(&str, &str)]) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("d602-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert role");
    for (entity, action) in grants {
        let key = format!("{entity}.{action}");
        let privilege_id: Uuid = sqlx::query_scalar(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
             VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
             ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(&key)
        .fetch_one(db)
        .await
        .expect("ensure privilege");
        sqlx::query(
            "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("grant role privilege");
    }
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role");
    role_id
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let req = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Preference security events on either audit write path (header, or the
/// chainer's ingest queue).
async fn preference_events(db: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header \
                  WHERE entity_name = 'notification_preference') \
              + (SELECT COUNT(*) FROM audit_ingest \
                  WHERE payload->>'entity_name' = 'notification_preference')",
    )
    .fetch_one(db)
    .await
    .expect("count preference audit events")
}

fn items(doc: &Value) -> &Vec<Value> {
    doc["items"].as_array().expect("items array")
}

// ── U5: notification preferences ─────────────────────────────────────────────

#[tokio::test]
async fn preferences_require_a_session() {
    let system = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (status, _) = send(&app, "GET", PREFS, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn preferences_are_only_ever_the_callers_own() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let alice = seed_user(&db).await;
    let bob = seed_user(&db).await;
    let (alice_cookie, bob_cookie) = (session_cookie(alice), session_cookie(bob));

    let (status, doc) = send(&app, "GET", PREFS, Some(&alice_cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(items(&doc).is_empty());
    assert!(
        doc["categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "reminder"),
        "the reminder event category is always offered: {doc}"
    );

    let events_before = preference_events(&db).await;
    let mute = json!({"items": [{"category": "reminder", "channel": "email", "enabled": false}]});
    let (status, doc) = send(&app, "PUT", PREFS, Some(&alice_cookie), Some(mute.clone())).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(items(&doc).len(), 1);
    assert_eq!(items(&doc)[0]["enabled"], false);
    assert_eq!(
        preference_events(&db).await,
        events_before + 1,
        "a preference change writes exactly one security event, in its own transaction"
    );

    // Bob reads nothing of Alice's, and his own write is his own row.
    let (status, doc) = send(&app, "GET", PREFS, Some(&bob_cookie), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        items(&doc).is_empty(),
        "another user's rows are never readable: {doc}"
    );

    // No field can name another user: the body is refused, and nothing is
    // written for Alice.
    let naming_alice = json!({"items": [{"category": "reminder", "channel": "in_app",
                                         "enabled": false, "user_ref": alice}]});
    let (status, _) = send(&app, "PUT", PREFS, Some(&bob_cookie), Some(naming_alice)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let alice_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_preference WHERE user_ref = $1")
            .bind(alice)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        alice_rows, 1,
        "Bob's request must not touch Alice's preferences"
    );

    let (status, doc) = send(&app, "PUT", PREFS, Some(&bob_cookie), Some(mute)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM notification_preference WHERE user_ref = ANY($1) ORDER BY user_ref",
    )
    .bind(vec![alice, bob])
    .fetch_all(&db)
    .await
    .unwrap();
    let mut expected = vec![alice, bob];
    expected.sort();
    assert_eq!(owners, expected, "each user wrote exactly their own row");
}

#[tokio::test]
async fn a_stale_row_version_is_a_conflict() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let user = seed_user(&db).await;
    let cookie = session_cookie(user);

    let first = json!({"items": [{"category": "reminder", "channel": "email", "enabled": false}]});
    let (status, doc) = send(&app, "PUT", PREFS, Some(&cookie), Some(first.clone())).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let row_version = items(&doc)[0]["row_version"].as_i64().unwrap();

    // Re-sending "no row yet" once a row exists is stale.
    let (status, _) = send(&app, "PUT", PREFS, Some(&cookie), Some(first)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let wrong = json!({"items": [{"category": "reminder", "channel": "email", "enabled": true,
                                  "row_version": row_version + 7}]});
    let (status, _) = send(&app, "PUT", PREFS, Some(&cookie), Some(wrong)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let right = json!({"items": [{"category": "reminder", "channel": "email", "enabled": true,
                                  "row_version": row_version}]});
    let (status, doc) = send(&app, "PUT", PREFS, Some(&cookie), Some(right)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(items(&doc)[0]["enabled"], true);
    assert_eq!(
        items(&doc)[0]["row_version"].as_i64().unwrap(),
        row_version + 1
    );
}

#[tokio::test]
async fn a_mandatory_template_or_unknown_category_cannot_be_muted() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let user = seed_user(&db).await;
    let cookie = session_cookie(user);

    let mandatory = format!("d602_mandatory_{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO notification_template \
             (template_key, locale, subject, body_text, is_mandatory, is_active) \
         VALUES ($1, 'en', 's', 'b', TRUE, TRUE)",
    )
    .bind(&mandatory)
    .execute(&db)
    .await
    .expect("insert mandatory template");

    let (_, doc) = send(&app, "GET", PREFS, Some(&cookie), None).await;
    assert!(
        !doc["categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == &json!(mandatory)),
        "a mandatory template is never offered"
    );
    for category in [mandatory.as_str(), "no_such_category"] {
        let body = json!({"items": [{"category": category, "channel": "email", "enabled": false}]});
        let (status, _) = send(&app, "PUT", PREFS, Some(&cookie), Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{category}");
    }
}

// ── U4: record reminders ─────────────────────────────────────────────────────

/// A fresh entity with one text field, and one record in it, created by the
/// admin. Returns (entity logical name, record id).
async fn record_fixture(
    app: &axum::Router,
    admin_cookie: &str,
    state: &EngineState,
) -> (String, String) {
    let logicalname = format!("d602_{}", Uuid::now_v7().simple());
    let (status, entity) = send(
        app,
        "POST",
        "/api/v1/admin/entities",
        Some(admin_cookie),
        Some(json!({"logicalname": logicalname, "name": "D-602 target"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}");
    let entity_id = entity["id"].as_str().unwrap().to_owned();
    let (status, field) = send(
        app,
        "POST",
        &format!("/api/v1/admin/entities/{entity_id}/fields"),
        Some(admin_cookie),
        Some(json!({"logicalname": "title", "name": "Title", "field_type": "text"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{field}");
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build registry");
    state.entities.swap(registry);

    let (status, record) = send(
        app,
        "POST",
        &format!("/api/v1/{logicalname}"),
        Some(admin_cookie),
        Some(json!({"title": "remind me about this"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    (logicalname, record["id"].as_str().unwrap().to_owned())
}

fn reminder_body(user: Uuid, entity: &str, record: &str, remind_at: &str) -> Value {
    json!({
        "user_ref": user,
        "entity_name": entity,
        "record_id": record,
        "remind_at": remind_at,
        "note": "call back",
        "status": "pending",
    })
}

/// A user who may read `entity`'s records and create/read/update reminders.
async fn reminder_user(db: &PgPool, entity: &str) -> (Uuid, String, Uuid) {
    let user = seed_user(db).await;
    let role = grant(
        db,
        user,
        &[
            (entity, "read"),
            ("reminder", "create"),
            ("reminder", "read"),
            ("reminder", "update"),
        ],
    )
    .await;
    (user, session_cookie(user), role)
}

fn past() -> String {
    (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339()
}

async fn dispatches_for(db: &PgPool, user: Uuid, record: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_dispatch \
         WHERE recipient_user_ref = $1 AND route LIKE '%' || $2",
    )
    .bind(user)
    .bind(record)
    .fetch_one(db)
    .await
    .unwrap()
}

async fn reminder_state(db: &PgPool, id: &str) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT status, status_reason FROM reminder WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_non_admin_cannot_set_a_reminder_for_someone_else() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (_, admin_cookie) = seed_admin(&db).await;
    let (entity, record) = record_fixture(&app, &admin_cookie, &state).await;
    let (user, cookie, _) = reminder_user(&db, &entity).await;
    let someone_else = seed_user(&db).await;
    let later = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    let (status, body) = send(
        &app,
        "POST",
        "/api/v1/reminder",
        Some(&cookie),
        Some(reminder_body(someone_else, &entity, &record, &later)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, created) = send(
        &app,
        "POST",
        "/api/v1/reminder",
        Some(&cookie),
        Some(reminder_body(user, &entity, &record, &later)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    // Nor can an update hand it to somebody else.
    let id = created["id"].as_str().unwrap();
    let row_version = created["row_version"].as_i64().unwrap();
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/reminder/{id}"))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(json!({"user_ref": someone_else}).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // An admin may set one for anyone.
    let (status, body) = send(
        &app,
        "POST",
        "/api/v1/reminder",
        Some(&admin_cookie),
        Some(reminder_body(someone_else, &entity, &record, &later)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn a_reminder_is_delivered_exactly_once_across_two_concurrent_sweeps() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (_, admin_cookie) = seed_admin(&db).await;
    let (entity, record) = record_fixture(&app, &admin_cookie, &state).await;
    let (user, cookie, _) = reminder_user(&db, &entity).await;

    let (status, created) = send(
        &app,
        "POST",
        "/api/v1/reminder",
        Some(&cookie),
        Some(reminder_body(user, &entity, &record, &past())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();

    // `EngineSystem::build` also spawned the real poller, which may race these
    // two sweeps for the same row too: three contenders, still one dispatch.
    let access = EngineReminderAccess;
    let (a, b) = tokio::join!(
        run_due_reminders(&state, &access as &dyn ReminderRecordAccess, 50),
        run_due_reminders(&state, &access as &dyn ReminderRecordAccess, 50),
    );
    a.expect("sweep a");
    b.expect("sweep b");
    // A third, later sweep finds nothing left to do for it either.
    run_due_reminders(&state, &access, 50)
        .await
        .expect("sweep c");

    assert_eq!(
        dispatches_for(&db, user, &record).await,
        1,
        "exactly one dispatch"
    );
    assert_eq!(reminder_state(&db, &id).await.0.as_deref(), Some("sent"));

    // It reaches the bell as an ordinary in-app notification, with a route
    // back to the record.
    let (route, title): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT r.route, r.title FROM notification_recipient r \
         JOIN notification_dispatch d ON d.id = r.dispatch_ref \
         WHERE r.user_ref = $1 AND d.route LIKE '%' || $2",
    )
    .bind(user)
    .bind(&record)
    .fetch_one(&db)
    .await
    .expect("one in-app row");
    assert_eq!(
        route.as_deref(),
        Some(format!("/{}/form?id={record}", entity.replace('_', "/")).as_str())
    );
    assert_eq!(title.as_deref(), Some("Reminder"));
}

#[tokio::test]
async fn a_reminder_on_a_record_that_became_invisible_is_dismissed_not_delivered() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (_, admin_cookie) = seed_admin(&db).await;
    let (entity, record) = record_fixture(&app, &admin_cookie, &state).await;
    let (user, cookie, role) = reminder_user(&db, &entity).await;

    // Set for later, so the poller `EngineSystem::build` spawned cannot deliver
    // it before the read is revoked; made due only afterwards.
    let later = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, created) = send(
        &app,
        "POST",
        "/api/v1/reminder",
        Some(&cookie),
        Some(reminder_body(user, &entity, &record, &later)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();

    // The user loses read on the record's entity after setting the reminder.
    sqlx::query(
        "DELETE FROM role_mm_privilege WHERE role_ref = $1 AND privilege_ref = \
         (SELECT id FROM privilege WHERE key = $2)",
    )
    .bind(role)
    .bind(format!("{entity}.read"))
    .execute(&db)
    .await
    .expect("revoke read");
    state.base.security.invalidate(user).await;
    sqlx::query("UPDATE reminder SET remind_at = NOW() - INTERVAL '1 minute' WHERE id = $1::uuid")
        .bind(&id)
        .execute(&db)
        .await
        .expect("make the reminder due");

    run_due_reminders(&state, &EngineReminderAccess, 50)
        .await
        .expect("sweep");

    assert_eq!(
        dispatches_for(&db, user, &record).await,
        0,
        "nothing delivered"
    );
    let (status, reason) = reminder_state(&db, &id).await;
    assert_eq!(status.as_deref(), Some("dismissed"));
    assert_eq!(reason.as_deref(), Some(REASON_RECORD_NOT_VISIBLE));
}
