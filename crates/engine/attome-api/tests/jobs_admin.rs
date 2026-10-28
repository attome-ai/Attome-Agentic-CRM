//! P-job-queue-hardening (D-165) — `GET /api/v1/admin/jobs/dead-letter` and
//! `POST /api/v1/admin/jobs/{id}/replay`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `authz.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test jobs_admin -- --test-threads=1
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

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn build_test_system() -> Option<EngineSystem> {
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

/// The system and router every test in this binary shares (build-loop plan,
/// Phase 3 task 4). Building a fresh `EngineSystem` per test cost ~0.3 s each;
/// the tests already share this binary's database, and each one provisions
/// its own uniquely named entities, users and roles, so sharing the in-memory
/// system adds no coupling the database did not already have. Tests run on
/// `attome_testkit::shared_runtime`, which keeps the pools' connections alive
/// between tests.
#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn state(&self) -> &EngineState {
        &self.state
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            Some(TestSystem {
                state,
                app: build_app(system),
            })
        })
        .await
        .clone()
}

fn full_app(system: TestSystem) -> axum::Router {
    system.app
}

fn build_app(system: EngineSystem) -> axum::Router {
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

async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("jobs-admin-test-{user_id}"))
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

    (user_id, session_cookie(user_id))
}

/// Seeds one `apalis.jobs` row directly (bypassing the real retry loop —
/// same shorthand `attome-jobs/tests/pending_count.rs` uses) so tests don't
/// have to actually burn through `max_attempts` to reach `Killed`.
async fn seed_dead_letter_row(
    db: &attome_db::DbPool,
    id: &str,
    job_type: &str,
    job: serde_json::Value,
    last_error: &str,
) {
    sqlx::query(
        "INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts, last_error, done_at) \
         VALUES ($1, $2, $3, 'Killed', 25, 25, $4, now())",
    )
    .bind(job)
    .bind(id)
    .bind(job_type)
    .bind(last_error)
    .execute(db)
    .await
    .expect("seed dead-letter apalis.jobs row");
}

#[test]
fn non_admin_gets_403_on_dead_letter_list_and_replay() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, non_admin_cookie) = seed_user(&system, false).await;
        let app = full_app(system);

        let list_req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/jobs/dead-letter")
            .header("cookie", &non_admin_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(list_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let replay_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/jobs/some-id/replay")
            .header("cookie", &non_admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(replay_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    })
}

#[test]
fn replay_on_a_row_that_is_not_dead_lettered_is_a_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let id = format!("jobs-admin-test-{}", Uuid::now_v7());
        sqlx::query(
            "INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts) \
         VALUES ('\"EnsureAuditPartitions\"', $1, 'attome_job', 'Pending', 0, 25)",
        )
        .bind(&id)
        .execute(&db)
        .await
        .expect("seed a still-pending row");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/jobs/{id}/replay"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a merely-Pending row must not be force-nudged through the replay path"
        );
    })
}

#[test]
fn replay_on_a_genuinely_dead_lettered_row_resets_it_to_pending() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let id = format!("jobs-admin-test-{}", Uuid::now_v7());
        seed_dead_letter_row(
            &db,
            &id,
            "attome_job",
            serde_json::json!("EnsureAuditPartitions"),
            "simulated failure",
        )
        .await;

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/jobs/{id}/replay"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        #[derive(sqlx::FromRow)]
        struct Row {
            status: String,
            attempts: i32,
            last_error: Option<String>,
        }
        let row: Row =
            sqlx::query_as("SELECT status, attempts, last_error FROM apalis.jobs WHERE id = $1")
                .bind(&id)
                .fetch_one(&db)
                .await
                .expect("fetch replayed row");
        assert_eq!(row.status, "Pending");
        assert_eq!(row.attempts, 0);
        assert_eq!(row.last_error, None);

        // Same predicate `apalis.get_jobs` uses to claim work — proves the row
        // is genuinely eligible again, not just cosmetically reset.
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM apalis.jobs WHERE id = $1 \
         AND (status = 'Pending' OR (status = 'Failed' AND attempts < max_attempts)) \
         AND run_at < now())",
        )
        .bind(&id)
        .fetch_one(&db)
        .await
        .expect("check get_jobs eligibility");
        assert!(eligible, "replayed row must be re-claimable by get_jobs");

        // Replaying it again must now 409 — it's no longer dead-lettered.
        let second_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/jobs/{id}/replay"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(second_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    })
}

#[test]
fn dead_letter_list_never_includes_the_raw_job_payload() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();

        let secret_marker = format!("SUPER-SECRET-RESET-TOKEN-{}", Uuid::now_v7());
        let id = format!("jobs-admin-test-{}", Uuid::now_v7());
        seed_dead_letter_row(
        &db,
        &id,
        "attome_job",
        serde_json::json!({
            "version": 1,
            "variant": "SendEmail",
            "payload": {
                "SendEmail": {
                    "to": "user@example.test",
                    "subject": "Reset your password",
                    "text_body": format!("Click here: https://example.test/reset?token={secret_marker}"),
                    "html_body": null
                }
            },
            "trace_context": null
        }),
        "smtp connection refused",
    )
    .await;

        let app = full_app(system);
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/jobs/dead-letter?queue=fast&page_size=200")
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            !body_text.contains(&secret_marker),
            "dead-letter list must never leak a SendEmail job's body/token: {body_text}"
        );
        assert!(
            !body_text.contains("text_body"),
            "dead-letter list must never surface the raw job payload at all: {body_text}"
        );

        let parsed: serde_json::Value = serde_json::from_str(&body_text).unwrap();
        let items = parsed["items"].as_array().expect("items array");
        let found = items
            .iter()
            .find(|item| item["id"].as_str() == Some(id.as_str()))
            .expect("seeded row must appear in the list");
        assert_eq!(found["variant"], "SendEmail");
        assert_eq!(found["attempts"], 25);
        assert_eq!(found["last_error"], "smtp connection refused");
    })
}

/// BJB-P0.3 / BJB-6b — a dead letter whose dedup slot a live row already holds
/// used to reach the operator as a masked 500, with the partial unique index
/// error as the only signal. It must be a 409 that names the reason instead of
/// the generic "not dead-lettered".
#[test]
fn replay_with_a_live_same_key_row_is_not_a_500() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        // Both rows carry the same (job_type, dedup_key): the live one holds the
        // slot the dead letter would need.
        let dedup = format!("jobs-admin-dedup-{}", Uuid::now_v7());
        let dead_id = format!("jobs-admin-dead-{}", Uuid::now_v7());
        let live_id = format!("jobs-admin-live-{}", Uuid::now_v7());
        let job = serde_json::json!("EnsureAuditPartitions");
        sqlx::query(
            "INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts, last_error, done_at, dedup_key) \
             VALUES ($1, $2, 'attome_job', 'Killed', 25, 25, 'simulated failure', now(), $3)",
        )
        .bind(job.clone())
        .bind(&dead_id)
        .bind(&dedup)
        .execute(&db)
        .await
        .expect("seed the dead-lettered row");
        sqlx::query(
            "INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts, dedup_key) \
             VALUES ($1, $2, 'attome_job', 'Pending', 0, 10, $3)",
        )
        .bind(job)
        .bind(&live_id)
        .bind(&dedup)
        .execute(&db)
        .await
        .expect("seed the live row holding the dedup slot");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/jobs/{dead_id}/replay"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a live dedup slot is a 409, never a masked 500"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("dedup key"),
            "the refusal must name the reason, got: {text}"
        );

        // The live row is untouched: replay must not disturb what is in flight.
        let status: String = sqlx::query_scalar("SELECT status FROM apalis.jobs WHERE id = $1")
            .bind(&live_id)
            .fetch_one(&db)
            .await
            .expect("fetch live row status");
        assert_eq!(status, "Pending");
    })
}

/// BJB-6c — a dead letter that will never be replayed can be discarded instead
/// of sitting until the retention sweep deletes it untriaged (BJB-F9).
#[test]
fn a_dead_letter_can_be_discarded() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let id = format!("jobs-admin-discard-{}", Uuid::now_v7());
        seed_dead_letter_row(
            &db,
            &id,
            "attome_job",
            serde_json::json!("SendEmail"),
            "simulated failure",
        )
        .await;

        let discard = || {
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/jobs/{id}"))
                .header("cookie", &admin_cookie)
                .header("origin", "http://localhost:4200")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap()
        };

        let resp = app.clone().oneshot(discard()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apalis.jobs WHERE id = $1")
            .bind(&id)
            .fetch_one(&db)
            .await
            .expect("count the row");
        assert_eq!(remaining, 0, "the dead letter must be gone");

        // A second discard names the same condition the first did: the status
        // guard is race-safe, so this is a 409 rather than a 404 or a 500.
        let again = app.clone().oneshot(discard()).await.unwrap();
        assert_eq!(again.status(), StatusCode::CONFLICT);
    })
}

/// AA10-T7: the operations list's ids for a caller, following every page.
async fn operation_ids(app: &axum::Router, cookie: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let uri = match &cursor {
            Some(c) => format!("/api/v1/admin/operations?page_size=200&cursor={c}"),
            None => "/api/v1/admin/operations?page_size=200".to_owned(),
        };
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for item in page["items"].as_array().unwrap() {
            out.push((
                item["id"].as_str().unwrap().to_owned(),
                item["kind"].as_str().unwrap().to_owned(),
            ));
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return out,
        }
    }
}

#[test]
fn operations_list_shows_mass_and_bulk() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (owner, owner_cookie) = seed_user(&system, false).await;
        let (_, other_cookie) = seed_user(&system, false).await;
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let mass: Uuid = sqlx::query_scalar(
            "INSERT INTO heavy_operation (kind, entity_logicalname, filter, payload, status, estimated_rows, started_by, reason) \
             VALUES ('update', 'account', '{}', '{}', 'running', 1200, $1, 'tidy regions') RETURNING id",
        )
        .bind(owner)
        .fetch_one(&db)
        .await
        .expect("seed a mass operation");
        let bulk: Uuid = sqlx::query_scalar(
            "INSERT INTO automation_bulk_operation (entity_logicalname, operation, status, total, succeeded, created_by) \
             VALUES ('account', 'update', 'completed', 10, 10, $1) RETURNING id",
        )
        .bind(owner)
        .fetch_one(&db)
        .await
        .expect("seed a bulk operation");
        let mass = (mass.to_string(), "mass".to_owned());
        let bulk = (bulk.to_string(), "bulk".to_owned());

        let own = operation_ids(&app, &owner_cookie).await;
        assert!(own.contains(&mass) && own.contains(&bulk), "{own:?}");
        let other = operation_ids(&app, &other_cookie).await;
        assert!(
            !other.contains(&mass) && !other.contains(&bulk),
            "{other:?}"
        );
        let all = operation_ids(&app, &admin_cookie).await;
        assert!(all.contains(&mass) && all.contains(&bulk));
        let mut seen = std::collections::HashSet::new();
        assert!(
            all.iter().all(|row| seen.insert(row.clone())),
            "no row on two pages"
        );
    })
}
