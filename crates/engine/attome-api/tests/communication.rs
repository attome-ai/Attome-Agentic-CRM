//! Integration coverage for M52 Phase 1 (D-465) — `attome_api::communication`'s
//! compose/reply routes.
//!
//! `retried_compose_with_the_same_idempotency_key_does_not_double_send` is
//! the concurrency/retry story coding-guidelines.md §2 requires for this
//! mutation: `attome_server::middleware::idempotency` is mounted globally
//! (`app.rs`'s `apply_inner_layers`), so it already wraps these two routes
//! with zero code in `communication.rs` itself — a retried request carrying
//! the same `x-idempotency-key` replays the first response instead of
//! re-running the handler, exactly like `attome-api/tests/idempotency.rs`'s
//! `same_key_same_endpoint_replays_the_cached_response` proves for
//! `POST /api/v1/admin/entities`. This test proves the same mechanism holds
//! for `compose`: a retry creates neither a second `communication` row
//! nor a second `communication_event` row (which would mean a second
//! `SendEmail` job — `write_communication` enqueues exactly one job per
//! event row, same transaction). A client that omits the header entirely is
//! NOT deduped at the mutation level — same posture as every other
//! non-`mandatory_operations` mutating route on this platform (see
//! `idempotency.rs`'s own module doc); promoting these two routes to
//! `idempotency.mandatory_operations` (the durable Postgres tier `bulk.rs`'s
//! `enqueue` already uses) is a natural follow-up if the product wants the
//! header to be contractually required.
//!
//! `compose_then_reply_thread_round_trips` is the happy-path coverage: a
//! fresh compose backfills `thread_id` to its own id, writes one `logged`
//! `communication` row and one `delivered` `communication_event`
//! child (channel=internal — no async transport step in Phase 1), and a
//! reply copies the thread root's `thread_id`, sets `in_reply_to` to its
//! parent, and prefixes an unprefixed subject with "Re: ".
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `idempotency.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test communication -- --test-threads=1
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
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["http://test.local"] }}
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

/// See `idempotency.rs`'s identical helper: `oneshot()` requests carry no
/// `Origin`/`Sec-Fetch-Site`, which `csrf_protect` fails closed on for
/// cookie-authenticated unsafe methods by design.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
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

/// A throwaway admin — `ctx.is_admin` short-circuits both the entity-level
/// `RecordScoped<Update>` check and the record-level `require_record_access`
/// DB predicate (`rls_predicate_with_conditions`: `if ctx.is_admin { return
/// None; }`, `attome-security/src/rls.rs`), so this session can compose/reply
/// against ANY existing record with no additional grant/entity setup — here,
/// its own `user_account` row, which already exists the moment the
/// user is inserted.
async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("comm-test-admin-{user_id}"))
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

/// A second throwaway, non-admin user — a plausible `channel=internal`
/// recipient. Not used as the record `compose`/`reply` target; only as a
/// `recipient_user_ids` value.
async fn seed_plain_user(system: &TestSystem) -> Uuid {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("comm-test-recipient-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway recipient user_account");
    user_id
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn communication_count(db: &attome_db::DbPool, entity_name: &str, record_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM communication WHERE entity_name = $1 AND record_id = $2",
    )
    .bind(entity_name)
    .bind(record_id.to_string())
    .fetch_one(db)
    .await
    .expect("count communication rows")
}

async fn event_count(db: &attome_db::DbPool, communication_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM communication_event WHERE communication_id = $1")
        .bind(communication_id)
        .fetch_one(db)
        .await
        .expect("count communication_event rows")
}

async fn event_types(db: &attome_db::DbPool, communication_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM communication_event \
         WHERE communication_id = $1 ORDER BY occurred_at",
    )
    .bind(communication_id)
    .fetch_all(db)
    .await
    .expect("event_type rows")
}

/// coding-guidelines.md §2: "make the underlying mutation retry-safe" via
/// HTTP idempotency. A client that retries the exact same compose request
/// (crashed before reading the response, a proxy timeout, a browser
/// double-submit) with the same `x-idempotency-key` must get the FIRST
/// send's cached response replayed, not a second `communication` row and
/// not a second `SendEmail` job — proven here by asserting exactly one
/// `communication` row and exactly one `communication_event` (the
/// `queued` row `write_communication` writes in the same transaction as the
/// job enqueue) exist after two identical requests.
#[test]
fn retried_compose_with_the_same_idempotency_key_does_not_double_send() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let idem_key = format!("comm-idem-{}", Uuid::now_v7());

        let build_req = || {
            Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/user_account/{admin_id}/communications"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("x-idempotency-key", &idem_key)
            .body(Body::from(
                r#"{"channel":"email","to":["recipient@example.test"],"subject":"Retry test","body":"hello"}"#,
            ))
            .unwrap()
        };

        let res1 = app.clone().oneshot(build_req()).await.expect("first send");
        assert_eq!(res1.status(), StatusCode::CREATED);
        let body1 = body_json(res1).await;
        let id1 = body1["id"].as_str().expect("communication id").to_owned();
        let comm_id: Uuid = id1.parse().expect("communication id is a uuid");

        let res2 = app
            .clone()
            .oneshot(build_req())
            .await
            .expect("retried send");
        assert_eq!(
            res2.status(),
            StatusCode::CREATED,
            "the replayed response must carry the same cached status"
        );
        let body2 = body_json(res2).await;
        assert_eq!(
            body2["id"].as_str().unwrap(),
            id1,
            "the retry must replay the first response's communication id, \
         not compose a second message"
        );

        assert_eq!(
            communication_count(&db, "user_account", admin_id).await,
            1,
            "a retried compose with the same idempotency key must create exactly \
         one communication row, not two"
        );
        assert_eq!(
            event_count(&db, comm_id).await,
            1,
            "a retried compose with the same idempotency key must enqueue exactly \
         one SendEmail job (one communication_event 'queued' row), not \
         a second email send"
        );
    })
}

/// REVIEW-2026-09-02 finding #4: compose's email loop used to enqueue
/// `SendEmail` for every address unconditionally, never consulting
/// `email_suppression` — a bounced or withdrawn address
/// could be emailed through compose even though a direct M51 dispatch
/// (`attome_notification::dispatch::create_dispatch`) already refuses it. This
/// proves the fix: composing to a suppressed address records exactly one
/// `suppressed` event row and never reaches the `queued`/`SendEmail` path.
#[test]
fn composing_to_a_suppressed_address_is_not_sent() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let suppressed_email = format!("suppressed-{}@example.test", Uuid::now_v7());
        sqlx::query("INSERT INTO email_suppression (email, reason) VALUES ($1, 'admin_manual')")
            .bind(&suppressed_email)
            .execute(&db)
            .await
            .expect("seed a suppression row");

        let app = full_app(system);
        let idem_key = format!("comm-suppressed-{}", Uuid::now_v7());
        let req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/user_account/{admin_id}/communications"
        ))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .header("x-idempotency-key", &idem_key)
        .body(Body::from(format!(
            r#"{{"channel":"email","to":["{suppressed_email}"],"subject":"Suppressed test","body":"hello"}}"#
        )))
        .unwrap();

        let res = app
            .oneshot(req)
            .await
            .expect("compose to a suppressed address");
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = body_json(res).await;
        let comm_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

        assert_eq!(
            event_types(&db, comm_id).await,
            vec!["suppressed".to_string()],
            "a suppressed address must produce exactly one 'suppressed' event \
         row and never a 'queued' one (which would mean SendEmail was \
         enqueued)"
        );
    })
}

/// Happy-path round trip: compose backfills its own `thread_id`, writes a
/// `logged` row (channel=internal has no async send step) and a `delivered`
/// event child; reply threads onto the root, prefixes the subject, and adds
/// a second event row scoped to the new message.
#[test]
fn compose_then_reply_thread_round_trips() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let recipient_id = seed_plain_user(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let compose_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/user_account/{admin_id}/communications"
        ))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"channel":"internal","recipient_user_ids":["{recipient_id}"],"subject":"Thread root","body":"first message"}}"#
        )))
        .unwrap();
        let compose_res = app.clone().oneshot(compose_req).await.expect("compose");
        assert_eq!(compose_res.status(), StatusCode::CREATED);
        let compose_body = body_json(compose_res).await;
        let root_id: Uuid = compose_body["id"]
            .as_str()
            .expect("communication id")
            .parse()
            .expect("uuid");
        let root_thread_id: Uuid = compose_body["thread_id"]
            .as_str()
            .expect("thread_id")
            .parse()
            .expect("uuid");
        assert_eq!(
            root_thread_id, root_id,
            "a fresh compose must backfill thread_id to its own id"
        );
        assert_eq!(compose_body["status"].as_str().unwrap(), "logged");

        #[derive(sqlx::FromRow)]
        struct Row {
            thread_id: Option<Uuid>,
            in_reply_to: Option<Uuid>,
            direction: Option<String>,
            channel: Option<String>,
            subject: Option<String>,
        }
        let root_row: Row = sqlx::query_as(
            "SELECT thread_id, in_reply_to, direction, channel, subject \
         FROM communication WHERE id = $1",
        )
        .bind(root_id)
        .fetch_one(&db)
        .await
        .expect("fetch root row");
        assert_eq!(root_row.thread_id, Some(root_id));
        assert_eq!(root_row.in_reply_to, None);
        assert_eq!(root_row.direction.as_deref(), Some("outbound"));
        assert_eq!(root_row.channel.as_deref(), Some("internal"));
        assert_eq!(root_row.subject.as_deref(), Some("Thread root"));

        let root_event_type: String = sqlx::query_scalar(
            "SELECT event_type FROM communication_event WHERE communication_id = $1",
        )
        .bind(root_id)
        .fetch_one(&db)
        .await
        .expect("fetch root event");
        assert_eq!(
            root_event_type, "delivered",
            "channel=internal has no async transport step — the write itself IS \
         the delivery, so the event lands as 'delivered' not 'queued'"
        );

        let reply_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/user_account/{admin_id}/communications/{root_id}/reply"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"body":"a reply"}"#))
            .unwrap();
        let reply_res = app.clone().oneshot(reply_req).await.expect("reply");
        assert_eq!(reply_res.status(), StatusCode::CREATED);
        let reply_body = body_json(reply_res).await;
        let reply_id: Uuid = reply_body["id"]
            .as_str()
            .expect("communication id")
            .parse()
            .expect("uuid");
        assert_ne!(reply_id, root_id, "a reply must be a new row, not the root");
        assert_eq!(
            reply_body["thread_id"].as_str().unwrap(),
            root_id.to_string(),
            "a reply must copy the thread ROOT's id, unchanged"
        );

        let reply_row: Row = sqlx::query_as(
            "SELECT thread_id, in_reply_to, direction, channel, subject \
         FROM communication WHERE id = $1",
        )
        .bind(reply_id)
        .fetch_one(&db)
        .await
        .expect("fetch reply row");
        assert_eq!(reply_row.thread_id, Some(root_id));
        assert_eq!(reply_row.in_reply_to, Some(root_id));
        assert_eq!(
            reply_row.subject.as_deref(),
            Some("Re: Thread root"),
            "an unprefixed parent subject must be prefixed with 'Re: ' on reply"
        );

        assert_eq!(
            communication_count(&db, "user_account", admin_id).await,
            2,
            "the thread must now have exactly two messages: the root and the reply"
        );
        assert_eq!(
            event_count(&db, reply_id).await,
            1,
            "the reply must get its own delivery-status event row"
        );
    })
}

/// J1-T1: an email composed for later carries the author's signature in the
/// stored row and its `SendEmail` job waits for `send_at`.
#[test]
fn scheduled_compose_is_signed_and_waits_for_send_at() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/me/email-signature")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"body":"Sara Ali\nSales","row_version":0}"#))
                    .unwrap(),
            )
            .await
            .expect("set the signature");
        assert_eq!(res.status(), StatusCode::OK);

        let send_at = chrono::Utc::now() + chrono::Duration::hours(3);
        let to = format!("later-{}@example.test", Uuid::now_v7());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/user_account/{admin_id}/communications"))
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .header(
                        "x-idempotency-key",
                        format!("comm-later-{}", Uuid::now_v7()),
                    )
                    .body(Body::from(
                        serde_json::json!({
                            "channel": "email",
                            "to": [to],
                            "subject": "Later",
                            "body": "See you then.",
                            "send_at": send_at.to_rfc3339(),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("compose for later");
        assert_eq!(res.status(), StatusCode::CREATED);
        let comm_id: Uuid = body_json(res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let stored: String = sqlx::query_scalar("SELECT body FROM communication WHERE id = $1")
            .bind(comm_id)
            .fetch_one(&db)
            .await
            .expect("the communication row");
        assert_eq!(stored, "See you then.\n\n-- \nSara Ali\nSales");

        let run_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT run_at FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'",
        )
        .bind(comm_id.to_string())
        .fetch_one(&db)
        .await
        .expect("the SendEmail job");
        assert!(
            (run_at - send_at).num_seconds().abs() <= 1,
            "the job runs at send_at, not now: {run_at} vs {send_at}"
        );
    })
}
