//! AG1-T9: the Hijri calendar end to end — a report grouped by Umm al-Qura
//! year, an autonumber carrying the Hijri year on a record created through
//! the generic entity API, and the holiday route refusing a Hijri date
//! outside the reference table — with the negative and permission paths.
//!
//! Every test provisions its own throwaway entity or calendar, so the suite
//! passes when run again on the same database.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`):
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-api --test hijri_end_to_end"
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool; production code uses attome_db::tx::begin"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_core::data_definition::DataDefinition;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::NaiveDate;
use serde_json::{Value, json};
use sqlx::PgPool;
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
        .register(attome_search::SearchModel)
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

async fn seed_user(db: &PgPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("ag1-e2e-user-{user_id}"))
    .bind(attome_testkit::unique_email("ag1e2e"))
    .execute(db)
    .await
    .expect("insert throwaway user");
    user_id
}

async fn seed_admin(db: &PgPool) -> Uuid {
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
    user_id
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie);
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

/// A throwaway entity with the given `(attribute, type)` pairs, registered
/// in the in-process metadata registry the way boot does.
async fn provision(system: &EngineSystem, prefix: &str, attributes: &[(&str, &str)]) -> String {
    let db = &system.state().base.db;
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let entity_id =
        attome_metadata::provision::ensure_entity(db, &logicalname, "Hijri Test", None, false)
            .await
            .expect("provision entity");
    for (name, field_type) in attributes {
        attome_metadata::provision::ensure_attribute(
            db, entity_id, name, name, field_type, false, false, true, true, None, None,
        )
        .await
        .expect("provision attribute");
    }
    let registry = attome_core::build_registry(db)
        .await
        .expect("build_registry");
    system.state().entities.swap(registry);
    logicalname
}

fn definition(raw: Value) -> DataDefinition {
    serde_json::from_value(raw).expect("test definition deserializes")
}

/// Records on either side of 1 Muharram 1447 (2025-06-26) fall in two
/// Hijri-year buckets, labelled by Hijri year, each counting its own rows;
/// a Hijri bucket over a field that is not a date is refused.
#[tokio::test]
async fn report_groups_by_hijri_year() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let deals = provision(
        &system,
        "ag1_hijri_deal",
        &[("closed_on", "date"), ("region", "text")],
    )
    .await;
    for closed_on in [
        "2025-01-15T10:00:00Z", // Rajab 1446
        "2025-03-20T10:00:00Z", // Ramadan 1446
        "2025-08-15T10:00:00Z", // Safar 1447
    ] {
        sqlx::query(&format!(
            "INSERT INTO \"{deals}\" (id, closed_on, region, is_active) \
             VALUES ($1, $2::timestamptz, 'GCC', true)"
        ))
        .bind(Uuid::now_v7())
        .bind(closed_on)
        .execute(&db)
        .await
        .expect("insert deal");
    }
    let admin = seed_admin(&db).await;
    let ctx = system
        .state()
        .base
        .security
        .resolve(admin)
        .await
        .expect("resolve admin context");
    let riyadh: chrono_tz::Tz = "Asia/Riyadh".parse().unwrap();

    let yearly = definition(json!({
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "closed_on", "bucket": "hijri_year" },
    }));
    let result =
        attome_search::run_structured_aggregate(system.state(), &ctx, &yearly, &[], riyadh)
            .await
            .expect("hijri-year aggregate");
    let buckets: Vec<(String, i64)> = result
        .buckets
        .iter()
        .map(|b| (b.label.clone().unwrap(), b.values[0].unwrap() as i64))
        .collect();
    assert_eq!(
        buckets,
        vec![("1446".to_string(), 2), ("1447".to_string(), 1)]
    );

    // The month bucket names the Hijri month too.
    let monthly = definition(json!({
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "closed_on", "bucket": "hijri_month" },
    }));
    let result =
        attome_search::run_structured_aggregate(system.state(), &ctx, &monthly, &[], riyadh)
            .await
            .expect("hijri-month aggregate");
    let labels: Vec<String> = result
        .buckets
        .iter()
        .map(|b| b.label.clone().unwrap())
        .collect();
    assert_eq!(labels, vec!["1446-07", "1446-09", "1447-02"]);

    // A Hijri bucket needs a date field.
    let wrong = definition(json!({
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "region", "bucket": "hijri_year" },
    }));
    let refused =
        attome_search::run_structured_aggregate(system.state(), &ctx, &wrong, &[], riyadh).await;
    assert!(
        matches!(refused, Err(attome_types::AppError::Validation(_))),
        "{refused:?}"
    );
}

/// A record created through the generic entity API takes its number from an
/// Auto Value rule carrying the Hijri year; a caller cannot pick the number.
#[tokio::test]
async fn autonumber_uses_hijri_year() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    attome_metadata::autovalue::seed_for_tests(&db)
        .await
        .expect("seed the autovalue entity");
    let entity = provision(&system, "ag1_hijri_doc", &[("code", "text")]).await;
    sqlx::query(
        "INSERT INTO autovalue \
             (id, name, entity_logicalname, attribute_logicalname, format, \
              initial_value, next_value, reset_scope, is_active, row_version) \
         VALUES ($1, 'AG1-T9 hijri numbering', $2, 'code', 'X-{hyyyy}-{SEQ:2}', \
                 1, 1, 'hijri_yearly', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(&entity)
    .execute(&db)
    .await
    .expect("insert autovalue rule");
    let app = full_app(system);
    let cookie = session_cookie(seed_admin(&db).await);

    // The deployment has no time zone configured: today is a UTC day.
    let year = attome_core::calendar::hijri::to_hijri(chrono::Utc::now().date_naive())
        .expect("today is in the reference table")
        .year;
    let mut codes = Vec::new();
    for _ in 0..2 {
        let (status, body) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &cookie,
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = body["id"]
            .as_str()
            .or_else(|| body["data"]["id"].as_str())
            .and_then(|id| Uuid::parse_str(id).ok())
            .unwrap_or_else(|| panic!("a created record carries its id: {body}"));
        let code: Option<String> =
            sqlx::query_scalar(&format!("SELECT code FROM \"{entity}\" WHERE id = $1"))
                .bind(id)
                .fetch_one(&db)
                .await
                .expect("read the numbered record");
        codes.push(code.unwrap_or_default());
    }
    assert_eq!(codes, vec![format!("X-{year}-01"), format!("X-{year}-02")]);

    let (status, body) = send(
        &app,
        "POST",
        &format!("/api/v1/{entity}"),
        &cookie,
        Some(json!({ "code": "X-1400-99" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

/// A holiday by a Hijri date outside the reference table (1356–1500) is a
/// 422, a date inside it lands on its Gregorian day, and a caller without
/// the administrator privilege is refused before either.
#[tokio::test]
async fn out_of_range_hijri_date_is_422() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let admin = session_cookie(seed_admin(&db).await);
    let user = session_cookie(seed_user(&db).await);

    let (status, calendar) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars",
        &admin,
        Some(json!({
            "name": format!("ag1-e2e-{}", Uuid::now_v7().simple()),
            "tz": "Asia/Riyadh",
            "working_days": [],
            "hours": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{calendar}");
    let path = format!(
        "/api/v1/admin/calendars/{}/holidays",
        calendar["id"].as_str().unwrap()
    );

    let (status, body) = send(
        &app,
        "POST",
        &path,
        &admin,
        Some(json!({"name": "Far future", "hijri_date": {"year": 1600, "month": 1, "day": 1}})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    let (status, _) = send(
        &app,
        "POST",
        &path,
        &user,
        Some(json!({"name": "Not mine", "hijri_date": {"year": 1447, "month": 10, "day": 1}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, holiday) = send(
        &app,
        "POST",
        &path,
        &admin,
        Some(json!({"name": "Eid al-Fitr", "hijri_date": {"year": 1447, "month": 10, "day": 1}})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{holiday}");
    let expected: NaiveDate = attome_core::calendar::hijri::HijriCalendar::umm_al_qura()
        .to_gregorian(attome_core::calendar::hijri::HijriDate {
            year: 1447,
            month: 10,
            day: 1,
        })
        .expect("1 Shawwal 1447 is in the table");
    assert_eq!(holiday["holiday_date"], expected.to_string());
}
