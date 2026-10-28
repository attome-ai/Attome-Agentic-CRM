//! Z12-T6: calendar rules, sightings, assignments and inheritance through the
//! admin API, checked against what the calendar loader then answers.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`):
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-api --test calendar_v2"
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
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Datelike, NaiveDate};
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
    let req = match &body {
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
    // S2-T10: an example for the API document, when ATTOME_CAPTURE_EXAMPLES is set.
    attome_testkit::examples::capture_example(method, uri, body.as_ref(), status.as_u16(), &json);
    (status, json)
}

/// A throwaway calendar, Sunday to Thursday 8 to 4 in Riyadh.
async fn new_calendar(app: &axum::Router, cookie: &str, parent: Option<Uuid>) -> Uuid {
    let mut body = json!({
        "name": format!("z12t6-{}", Uuid::now_v7().simple()),
        "tz": "Asia/Riyadh",
        "working_days": ["sun", "mon", "tue", "wed", "thu"],
        "hours": {
            "sun": [{"start_minute": 480, "end_minute": 960}],
            "mon": [{"start_minute": 480, "end_minute": 960}],
            "tue": [{"start_minute": 480, "end_minute": 960}],
            "wed": [{"start_minute": 480, "end_minute": 960}],
            "thu": [{"start_minute": 480, "end_minute": 960}]
        },
        "country_code": "sa",
        "name_ar": "تقويم"
    });
    if let Some(parent) = parent {
        body["parent_calendar_id"] = json!(parent);
    }
    let (status, created) = send(app, "POST", "/api/v1/admin/calendars", cookie, Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["country_code"], "SA");
    created["id"].as_str().unwrap().parse().unwrap()
}

async fn holidays_of(db: &PgPool, calendar: Uuid) -> std::collections::BTreeSet<NaiveDate> {
    attome_core::calendar::load_calendar(db, calendar)
        .await
        .expect("load")
        .expect("usable calendar")
        .calendar
        .holidays()
        .clone()
}

const EID: &str = r#"{"kind": "hijri", "month": 10, "day": 1, "span_days": 3}"#;

#[tokio::test]
async fn hijri_rule_creates_eid_dates() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let cookie = session_cookie(seed_admin(&db).await);
    let app = full_app(system);
    let calendar = new_calendar(&app, &cookie, None).await;

    let (status, rule) = send(
        &app,
        "POST",
        &format!("/api/v1/admin/calendars/{calendar}/holiday-rules"),
        &cookie,
        Some(json!({ "name": "Eid al-Fitr", "rule": serde_json::from_str::<Value>(EID).unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{rule}");

    let year = chrono::Utc::now().year();
    let rule: attome_core::calendar::rules::HolidayRule = serde_json::from_str(EID).unwrap();
    let expected = attome_core::calendar::rules::expand(&rule, year).unwrap();
    let holidays = holidays_of(&db, calendar).await;
    for date in &expected {
        assert!(holidays.contains(date), "{date} is a holiday");
    }

    let (status, full) = send(
        &app,
        "GET",
        &format!("/api/v1/admin/calendars/{calendar}"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(full["rules"][0]["name"], "Eid al-Fitr");

    let (status, _) = send(
        &app,
        "POST",
        &format!("/api/v1/admin/calendars/{calendar}/holiday-rules"),
        &cookie,
        Some(json!({ "name": "Bad", "rule": { "kind": "fixed", "month": 13, "day": 1, "span_days": 1 } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn sighting_moves_eid() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let cookie = session_cookie(seed_admin(&db).await);
    let app = full_app(system);
    let calendar = new_calendar(&app, &cookie, None).await;
    let (status, rule) = send(
        &app,
        "POST",
        &format!("/api/v1/admin/calendars/{calendar}/holiday-rules"),
        &cookie,
        Some(json!({
            "name": "Eid al-Fitr",
            "rule": serde_json::from_str::<Value>(EID).unwrap(),
            "needs_sighting": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{rule}");
    let rule_id = rule["id"].as_str().unwrap().to_owned();

    let year = chrono::Utc::now().year();
    let (status, list) = send(
        &app,
        "GET",
        &format!("/api/v1/calendar-sightings?year={year}"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let ours = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["rule_id"] == rule_id.as_str())
        .expect("the rule's expected start")
        .clone();
    let expected: NaiveDate = ours["expected_start"].as_str().unwrap().parse().unwrap();
    let moved = expected.succ_opt().unwrap();

    let (status, confirmed) = send(
        &app,
        "POST",
        "/api/v1/calendar-sightings",
        &cookie,
        Some(json!({
            "rule_id": rule_id,
            "hijri_year": ours["hijri_year"],
            "confirmed_start": moved
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let holidays = holidays_of(&db, calendar).await;
    assert!(
        !holidays.contains(&expected),
        "the expected first day moved"
    );
    assert!(holidays.contains(&moved));

    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/calendar-sightings",
        &cookie,
        Some(json!({
            "rule_id": rule_id,
            "hijri_year": ours["hijri_year"],
            "confirmed_start": expected + chrono::Duration::days(10)
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "too far from the expected start"
    );
}

#[tokio::test]
async fn assignment_route_sets_user_calendar() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let cookie = session_cookie(seed_admin(&db).await);
    let app = full_app(system);
    let calendar = new_calendar(&app, &cookie, None).await;
    let person = seed_user(&db).await;
    let uri = format!("/api/v1/calendar-assignments/user/{person}");

    let (status, row) = send(
        &app,
        "PUT",
        &uri,
        &cookie,
        Some(json!({ "calendar_id": calendar })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{row}");
    assert_eq!(
        attome_core::calendar::resolve_calendar_id_for_user(&db, person)
            .await
            .unwrap(),
        Some(calendar)
    );
    let (status, _) = send(
        &app,
        "PUT",
        &uri,
        &cookie,
        Some(json!({ "calendar_id": calendar })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a change needs the row version"
    );
    let (status, _) = send(&app, "GET", &uri, &cookie, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, "DELETE", &uri, &cookie, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "GET", &uri, &cookie, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/calendar-assignments/robot/{person}"),
        &cookie,
        Some(json!({ "calendar_id": calendar })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn parent_cycle_rejected() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let cookie = session_cookie(seed_admin(&db).await);
    let app = full_app(system);
    let root = new_calendar(&app, &cookie, None).await;
    let child = new_calendar(&app, &cookie, Some(root)).await;

    // The root may not inherit from its own child.
    let (status, root_row) = send(
        &app,
        "GET",
        &format!("/api/v1/admin/calendars/{root}"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = json!({
        "name": root_row["name"],
        "tz": root_row["tz"],
        "working_days": root_row["working_days"],
        "hours": root_row["hours"],
        "parent_calendar_id": child
    });
    let (status, refused) = send(
        &app,
        "PATCH",
        &format!("/api/v1/admin/calendars/{root}"),
        &cookie,
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");

    // A fourth level is too deep.
    let grandchild = new_calendar(&app, &cookie, Some(child)).await;
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars",
        &cookie,
        Some(json!({
            "name": format!("z12t6-deep-{}", Uuid::now_v7().simple()),
            "tz": "Asia/Riyadh",
            "working_days": ["sun"],
            "hours": { "sun": [{"start_minute": 480, "end_minute": 960}] },
            "parent_calendar_id": grandchild
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Z12-T7: country holiday packs ───────────────────────────────────────────

/// Retires every Saudi calendar earlier tests left, so the pack's lookup by
/// country starts from none (this target runs with one test thread).
async fn clear_saudi_calendars(db: &PgPool) {
    sqlx::query(
        "UPDATE calendar SET is_active = false, is_default = false, \
                name = name || '-retired-' || id::text \
          WHERE (country_code = 'SA' OR name = 'Saudi Arabia') AND is_active = true",
    )
    .execute(db)
    .await
    .expect("retire earlier Saudi calendars");
}

#[tokio::test]
async fn apply_sa_pack_creates_calendar() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let cookie = session_cookie(seed_admin(&db).await);
    let app = full_app(system);
    clear_saudi_calendars(&db).await;

    let (status, packs) = send(&app, "GET", "/api/v1/admin/calendars/packs", &cookie, None).await;
    assert_eq!(status, StatusCode::OK, "{packs}");
    assert!(packs.as_array().unwrap().iter().any(|p| p["code"] == "sa"));

    let (status, applied) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars/packs/sa/apply",
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["created"], true);
    assert_eq!(applied["rules_changed"], 4);
    let calendar: Uuid = applied["calendar_id"].as_str().unwrap().parse().unwrap();

    let (status, detail) = send(
        &app,
        "GET",
        &format!("/api/v1/admin/calendars/{calendar}"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(detail["name"], "Saudi Arabia");
    assert_eq!(detail["country_code"], "SA");

    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM calendar_holiday_rule WHERE calendar_id = $1 AND is_active = true ORDER BY name",
    )
    .bind(calendar)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(
        names,
        ["Eid al-Adha", "Eid al-Fitr", "Founding Day", "National Day"]
    );
    let year = chrono::Utc::now().year();
    let holidays = holidays_of(&db, calendar).await;
    for (month, day) in [(2, 22), (9, 23)] {
        let date = NaiveDate::from_ymd_opt(year, month, day).unwrap();
        assert!(holidays.contains(&date), "{date} is a holiday");
    }
}

#[tokio::test]
async fn reapply_pack_is_idempotent() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let cookie = session_cookie(seed_admin(&db).await);
    let app = full_app(system);
    clear_saudi_calendars(&db).await;

    let (status, first) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars/packs/sa/apply",
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars/packs/SA/apply",
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["calendar_id"], first["calendar_id"]);
    assert_eq!(second["created"], false);
    assert_eq!(second["rules_changed"], 0);

    let calendars: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM calendar WHERE country_code = 'SA' AND is_active = true",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(calendars, 1);
    let calendar: Uuid = first["calendar_id"].as_str().unwrap().parse().unwrap();
    let rules: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM calendar_holiday_rule WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(rules, 4);

    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars/packs/zz/apply",
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Z12-T14: a branch calendar end to end. The SA pack makes the country
/// calendar; a branch inherits it with a short Thursday; a person assigned to
/// the branch gets 8 business hours from a Wednesday 15:00 in Riyadh on
/// Sunday at 11:00 (1 h Wednesday, 4 h Thursday, Friday and Saturday off,
/// 3 h Sunday); confirming a sighting moves the country calendar's version.
#[tokio::test]
async fn end_to_end_branch_calendar() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let admin = seed_admin(&db).await;
    let cookie = session_cookie(admin);
    let person = seed_user(&db).await;
    let app = full_app(system);
    clear_saudi_calendars(&db).await;

    let (status, applied) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars/packs/sa/apply",
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let country: Uuid = applied["calendar_id"].as_str().unwrap().parse().unwrap();

    let day = |start: u16, end: u16| json!([{ "start_minute": start, "end_minute": end }]);
    let (status, branch) = send(
        &app,
        "POST",
        "/api/v1/admin/calendars",
        &cookie,
        Some(json!({
            "name": format!("z12t14-branch-{}", Uuid::now_v7().simple()),
            "name_ar": "فرع",
            "tz": "Asia/Riyadh",
            "parent_calendar_id": country,
            "working_days": ["sun", "mon", "tue", "wed", "thu"],
            "hours": {
                "sun": day(480, 960), "mon": day(480, 960), "tue": day(480, 960),
                "wed": day(480, 960), "thu": day(480, 720)
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{branch}");
    let branch: Uuid = branch["id"].as_str().unwrap().parse().unwrap();

    let (status, assigned) = send(
        &app,
        "PUT",
        &format!("/api/v1/calendar-assignments/user/{person}"),
        &cookie,
        Some(json!({ "calendar_id": branch })),
    )
    .await;
    assert!(status.is_success(), "{status} {assigned}");

    // A Wednesday whose Thursday and Sunday are working days in the country
    // calendar, a few weeks out.
    let holidays = holidays_of(&db, country).await;
    let mut wednesday = chrono::Utc::now().date_naive() + chrono::Duration::days(21);
    while wednesday.weekday() != chrono::Weekday::Wed
        || [0, 1, 4]
            .iter()
            .any(|d| holidays.contains(&(wednesday + chrono::Duration::days(*d))))
    {
        wednesday = wednesday.succ_opt().unwrap();
    }
    // 15:00 in Riyadh (UTC+3, no daylight saving) is 12:00 UTC.
    let from = wednesday.and_hms_opt(12, 0, 0).unwrap().and_utc();
    let (status, answer) = send(
        &app,
        "POST",
        &format!("/api/v1/calendars/{country}/calculate"),
        &cookie,
        Some(json!({ "op": "add", "from": from, "minutes": 480, "user_id": person })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["calendar_id"],
        branch.to_string(),
        "the person's own calendar"
    );
    let result: chrono::DateTime<chrono::Utc> = answer["result"].as_str().unwrap().parse().unwrap();
    let sunday = wednesday + chrono::Duration::days(4);
    assert_eq!(
        result,
        sunday.and_hms_opt(8, 0, 0).unwrap().and_utc(),
        "Sunday 11:00 Riyadh"
    );

    // Confirming a sighting on the country calendar is a new version of it.
    let version = |detail: &Value| detail["current_version"].as_i64().unwrap();
    let (_, before) = send(
        &app,
        "GET",
        &format!("/api/v1/admin/calendars/{country}"),
        &cookie,
        None,
    )
    .await;
    let year = chrono::Utc::now().year();
    let (status, sightings) = send(
        &app,
        "GET",
        &format!("/api/v1/calendar-sightings?year={year}"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sightings}");
    let eid = sightings
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["calendar_id"] == country.to_string())
        .expect("a sighted holiday on the country calendar")
        .clone();
    let expected: NaiveDate = eid["expected_start"].as_str().unwrap().parse().unwrap();
    let (status, confirmed) = send(
        &app,
        "POST",
        "/api/v1/calendar-sightings",
        &cookie,
        Some(json!({
            "rule_id": eid["rule_id"],
            "hijri_year": eid["hijri_year"],
            "confirmed_start": expected.succ_opt().unwrap()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let (_, after) = send(
        &app,
        "GET",
        &format!("/api/v1/admin/calendars/{country}"),
        &cookie,
        None,
    )
    .await;
    assert!(version(&after) > version(&before), "{before} -> {after}");
}
