//! End-to-end tests for `GET /api/v1/search` (TODO-017), through the
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
//! cargo test -p attome-api --test search_routes -- --test-threads=1
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
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
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
        .bind(format!("search-routes-admin-{user_id}"))
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

/// No `inference` section in the JSON above, so this is `InferenceSection::
/// default()` — every AI switch off and no model endpoint. That is the
/// **default state of every deployment**, and testing against it is
/// deliberate: it is what a fresh install actually does.
async fn test_system() -> Option<(EngineSystem, attome_db::DbPool)> {
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

    // Fully licensed, so the route-level module gate is not what these tests
    // are measuring. `unlicensed_deployment_hides_the_whole_surface` below
    // flips it back off deliberately.
    let license = ModuleSet::from_bits([u64::MAX; 4]);
    state.modules.store(Arc::new(license));

    let system = EngineSystem::builder(state)
        .register(attome_search::SearchModel)
        .build()
        .await
        .expect("build EngineSystem");
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

// ── GET /api/v1/search ───────────────────────────────────────────────────────

async fn seed_indexed_row(db: &attome_db::DbPool, entity: &str, title: &str) -> Uuid {
    let record_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO search_index \
            (corpus, entity_logicalname, record_id, title, title_norm, \
             body_display, body_indexed, exact_keys, tsv) \
         VALUES ('record', $1, $2, $3, $4, $5, $6, $7, \
                 to_tsvector('attome_search', $6))",
    )
    .bind(entity)
    .bind(record_id)
    .bind(title)
    .bind(attome_search::normalize_ar(title))
    .bind("Invoice body")
    .bind(attome_search::index_text("Invoice body"))
    .bind(vec!["inv-5150".to_string()])
    .execute(db)
    .await
    .expect("seed an index row");
    record_id
}

/// The caps are enforced at the HTTP surface, not merely in a pure function.
#[tokio::test]
async fn the_query_caps_are_enforced_over_http() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let thirty_five_terms = "a%20".repeat(35);
    let cases: Vec<(String, &str)> = vec![
        ("/api/v1/search?q=".to_string(), "an empty query"),
        (
            format!("/api/v1/search?q={thirty_five_terms}"),
            "more terms than the cap",
        ),
        ("/api/v1/search?q=acme&page=0".to_string(), "page below one"),
        (
            "/api/v1/search?q=acme&page=999".to_string(),
            "page beyond the documented cap",
        ),
        (
            "/api/v1/search?q=acme&page_size=500".to_string(),
            "an oversized page",
        ),
        (
            "/api/v1/search?q=acme&audience=root".to_string(),
            "an unknown audience",
        ),
    ];

    for (uri, why) in cases {
        let (status, body) = get(&app, &uri, &cookie).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{why} must be rejected, not silently accepted: {body}"
        );
    }
}

/// An admin gets the seeded row back, with the route named and the total
/// honest.
#[tokio::test]
async fn a_search_returns_matching_rows_with_an_honest_total() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let entity = format!("test_search_{}", Uuid::now_v7().simple());
    let record_id = seed_indexed_row(&db, &entity, "ACME Trading LLC").await;
    let app = full_app(system);

    let (status, body) = get(&app, "/api/v1/search?q=acme%20trading", &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let ids: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|i| i["entity_logicalname"] == entity.as_str())
        .map(|i| i["record_id"].as_str().expect("record_id"))
        .collect();
    assert!(
        ids.contains(&record_id.to_string().as_str()),
        "the seeded row must be found: {body}"
    );

    // A small match set is EXACT, not a floor — the distinction the Total enum
    // exists to carry.
    assert_eq!(body["total"]["kind"], "exact", "{body}");
    assert!(
        body["route"].is_string(),
        "the route must be reported: {body}"
    );
    assert!(body["degraded"].is_array(), "{body}");

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}

/// Hits carry their display text.
///
/// The fused statement returns identity and score only — `title`/`subtitle`
/// would otherwise ride through every leg's CTE, the `UNION ALL` and the
/// `GROUP BY` for every candidate up to the ceiling, so they come from a second
/// read over the page. Without that read every result renders as "(untitled)",
/// which is a shipped feature that looks broken to every user while every test
/// about ids and ordering stays green.
#[tokio::test]
async fn hits_carry_the_title_the_ui_renders() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let entity = format!("test_search_{}", Uuid::now_v7().simple());
    let record_id = seed_indexed_row(&db, &entity, "Zenith Logistics FZE").await;
    let app = full_app(system);

    let (status, body) = get(&app, "/api/v1/search?q=zenith%20logistics", &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let hit = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|i| i["record_id"] == record_id.to_string().as_str())
        .unwrap_or_else(|| panic!("the seeded row must be found: {body}"));
    assert_eq!(
        hit["title"], "Zenith Logistics FZE",
        "the hit must carry its title, not null: {body}"
    );

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}

/// **The assertion the whole permission design exists for, at the HTTP
/// surface.** A caller holding no read privilege on the entity gets nothing
/// back for a row that plainly matches the query text.
#[tokio::test]
async fn a_caller_with_no_privilege_sees_no_results() {
    let (system, db) = skip_if_no_db!(test_system().await);
    // A bare authenticated user: no roles, no grants, no privileges.
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("search-nobody-{user_id}"))
        .execute(&db)
        .await
        .expect("insert bare user");
    let cookie = session_cookie(user_id);

    let entity = format!("test_search_{}", Uuid::now_v7().simple());
    seed_indexed_row(&db, &entity, "ACME Trading LLC").await;
    let app = full_app(system);

    let (status, body) = get(&app, "/api/v1/search?q=acme%20trading", &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let leaked: Vec<&serde_json::Value> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|i| i["entity_logicalname"] == entity.as_str())
        .collect();
    assert!(
        leaked.is_empty(),
        "a caller with no read privilege must see nothing — the row matches \
         the query text perfectly, so anything returned here is a disclosure: \
         {body}"
    );

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}

/// An aggregation question is routed away from retrieval and returns the tool
/// hint instead — rule 4, over HTTP. Reaching for semantic retrieval when the
/// question was arithmetic is where most bad copilot answers come from.
#[tokio::test]
async fn an_aggregation_question_returns_a_route_hint_not_results() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let (status, body) = get(
        &app,
        "/api/v1/search?q=how%20many%20open%20cases&audience=agent",
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["route"], "aggregation", "{body}");
    assert_eq!(body["route_hint"]["tool"], "query_records", "{body}");
    assert!(
        body["items"].as_array().expect("items").is_empty(),
        "an aggregation question must not be answered with retrieved rows: {body}"
    );
}

#[tokio::test]
async fn searching_requires_authentication() {
    let (system, _db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/search?q=acme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// An unlicensed deployment hides the surface entirely.
#[tokio::test]
async fn an_unlicensed_deployment_hides_search() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    system
        .state()
        .modules
        .store(Arc::new(ModuleSet::core_only()));
    let app = full_app(system);

    let (status, _) = get(&app, "/api/v1/search?q=acme", &cookie).await;
    assert_ne!(status, StatusCode::OK);
}

/// A search writes its impression, and the response carries the handle a click
/// is reported against (TODO-021).
///
/// The write is **spawned**, not awaited — a search must not be slower or fail
/// because a log table is busy — so this polls briefly rather than asserting
/// immediately. Polling is the honest shape here: asserting synchronously
/// would only pass by accident of timing, and adding an await to make the test
/// simple would remove the property the design exists for.
#[tokio::test]
async fn a_search_records_its_impression_off_the_request_path() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let entity = format!("test_search_{}", Uuid::now_v7().simple());
    seed_indexed_row(&db, &entity, "ACME Trading LLC").await;
    let app = full_app(system);

    let (status, body) = get(&app, "/api/v1/search?q=acme%20trading", &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let impression_id = body["impression_id"]
        .as_str()
        .expect("the response must carry the impression handle a click is reported against");
    let impression_id: Uuid = impression_id.parse().expect("a uuid");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let found: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM search_impression WHERE id = $1")
            .bind(impression_id)
            .fetch_one(&db)
            .await
            .expect("count impressions");
        if found == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the spawned impression write never landed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // The ranker is recorded — without it a log spanning a ranker change is
    // one population pretending to be two.
    let (ranker, route, audience): (String, String, String) =
        sqlx::query_as("SELECT ranker_id, route, audience FROM search_impression WHERE id = $1")
            .bind(impression_id)
            .fetch_one(&db)
            .await
            .expect("read impression");
    assert!(!ranker.is_empty(), "the ranker must be recorded");
    assert!(!route.is_empty());
    assert_eq!(audience, "human");

    // And no raw query text reached the row.
    let whole_row: String =
        sqlx::query_scalar("SELECT search_impression::text FROM search_impression WHERE id = $1")
            .bind(impression_id)
            .fetch_one(&db)
            .await
            .expect("read row as text");
    assert!(
        !whole_row.to_lowercase().contains("acme"),
        "query text must never be stored — only its keyed fingerprint: {whole_row}"
    );

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}

// ── GET /api/v1/admin/knowledge/coverage (chatbot plan C8) ───────────────────

/// This collection's coverage row, walking pages: the shared database holds
/// other tests' collections, and the read orders by name.
async fn coverage_row(app: &axum::Router, cookie: &str, collection: Uuid) -> Value {
    for page in 1..=1000 {
        let (status, body) = get(
            app,
            &format!("/api/v1/admin/knowledge/coverage?page={page}&page_size=100"),
            cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body["items"].as_array().expect("items");
        if let Some(row) = items
            .iter()
            .find(|c| c["collection_id"] == collection.to_string().as_str())
        {
            return row.clone();
        }
        assert!(
            !items.is_empty(),
            "collection {collection} is not in the coverage read"
        );
    }
    panic!("collection {collection} is not in the coverage read");
}

/// **The operator's coverage read, over the full stack.** An administrator
/// sees the collection with its published item chunked and its draft counted
/// but never chunked (D-489); the embedding figures follow the indexer's
/// configured model — `null` together when knowledge is lexical-only, and
/// `backlog = chunks - embedded` otherwise. A caller without `system.admin`
/// is refused both coverage routes.
#[tokio::test]
async fn the_knowledge_coverage_read_is_admin_only() {
    let (system, db) = skip_if_no_db!(test_system().await);
    attome_api::bundle::apply_platform_bundle(
        system.state(),
        "attome-webcrawl",
        include_str!("../../../../platform-bundles/attome-webcrawl.json"),
    )
    .await
    .expect("apply the knowledge bundle");
    let (_, admin_cookie) = seed_admin(&db).await;
    let reader = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(reader)
        .bind(format!("coverage-reader-{reader}"))
        .execute(&db)
        .await
        .expect("insert bare user");

    let collection = Uuid::now_v7();
    sqlx::query("INSERT INTO knowledge_data_source (id, name, is_active) VALUES ($1, $2, TRUE)")
        .bind(collection)
        .bind(format!("Coverage {}", collection.simple()))
        .execute(&db)
        .await
        .expect("collection");
    let (published, draft) = (Uuid::now_v7(), Uuid::now_v7());
    for (id, lifecycle) in [(published, "published"), (draft, "draft")] {
        sqlx::query(
            "INSERT INTO knowledge_data_item (id, title, text, data_source_ref, lifecycle, is_active) \
             VALUES ($1, 'Returns', '# Returns\n\nWithin thirty days.', $2, $3, TRUE)",
        )
        .bind(id)
        .bind(collection)
        .bind(lifecycle)
        .execute(&db)
        .await
        .expect("item");
        attome_search::reindex_item(&db, id).await.expect("reindex");
    }
    let app = full_app(system);

    let row = coverage_row(&app, &admin_cookie, collection).await;
    assert_eq!(row["items_total"], 2, "{row}");
    assert_eq!(row["items_published"], 1, "{row}");
    assert_eq!(row["items_draft"], 1, "{row}");
    let chunks = row["chunks"].as_i64().expect("chunks");
    assert!(chunks >= 1, "the published item is chunked: {row}");
    assert!(row["last_indexed_at"].is_string(), "{row}");

    let (status, indexer) = get(
        &app,
        "/api/v1/admin/knowledge/coverage/indexer",
        &admin_cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{indexer}");
    if indexer["embedding_model"].is_null() {
        assert!(
            row["chunks_embedded"].is_null() && row["embedding_backlog"].is_null(),
            "{row}"
        );
    } else {
        let embedded = row["chunks_embedded"].as_i64().expect("embedded");
        assert_eq!(
            row["embedding_backlog"].as_i64(),
            Some(chunks - embedded),
            "{row}"
        );
    }

    let reader_cookie = session_cookie(reader);
    for uri in [
        "/api/v1/admin/knowledge/coverage",
        "/api/v1/admin/knowledge/coverage/indexer",
    ] {
        let (status, body) = get(&app, uri, &reader_cookie).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }

    for item in [published, draft] {
        let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE source_id = $1")
            .bind(item)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM knowledge_data_item WHERE id = $1")
            .bind(item)
            .execute(&db)
            .await;
    }
    let _ = sqlx::query("DELETE FROM knowledge_data_source WHERE id = $1")
        .bind(collection)
        .execute(&db)
        .await;
}

/// AB5-T5: with the search index confirmed down, search answers from the
/// tables: a prefix match on each readable entity's title attribute, marked
/// `limited` with the route `fallback` and `search_index` degraded. A
/// sensitive attribute is never searched.
#[tokio::test]
async fn search_falls_back_when_index_down() {
    use attome_server::capability::{Capability, ProbeOutcome};
    let (system, db) = skip_if_no_db!(test_system().await);
    let (_user, cookie) = seed_admin(&db).await;
    let suffix = Uuid::now_v7().simple().to_string();
    // `a0` sorts first, inside the fallback's entity cap.
    let entity = format!("a0fb_{}", &suffix[20..]);
    let entity_id = attome_metadata::provision::ensure_entity(
        &db,
        &entity,
        "Fallback test",
        Some("name"),
        false,
    )
    .await
    .expect("provision entity");
    for (name, sensitive) in [("name", false), ("secret", true)] {
        attome_metadata::provision::ensure_attribute(
            &db, entity_id, name, name, "text", false, sensitive, false, false, None, None,
        )
        .await
        .expect("provision attribute");
    }
    let token = format!("fbco{}", &suffix[26..]);
    let named: Uuid = sqlx::query_scalar(&format!(
        "INSERT INTO \"{entity}\" (name, secret) VALUES ($1, 'x') RETURNING id"
    ))
    .bind(format!("{token} Trading"))
    .fetch_one(&db)
    .await
    .expect("insert the named record");
    sqlx::query(&format!(
        "INSERT INTO \"{entity}\" (name, secret) VALUES ('Other', $1)"
    ))
    .bind(format!("{token} hidden"))
    .execute(&db)
    .await
    .expect("insert the record matching only on a sensitive field");
    let state = system.state().clone();
    let registry = attome_core::build_registry(&db)
        .await
        .expect("build entity metadata registry");
    state.entities.swap(registry);
    let app = full_app(system);
    let uri = format!("/api/v1/search?q={token}");

    let (status, body) = get(&app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["route"], "fallback", "the index is not down: {body}");
    assert!(body.get("limited").is_none(), "{body}");

    for _ in 0..2 {
        state
            .base
            .capabilities
            .record(Capability::SearchIndex, ProbeOutcome::Unreachable);
    }
    let (status, body) = get(&app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["route"], "fallback", "{body}");
    assert_eq!(body["limited"], true, "{body}");
    assert!(
        body["degraded"]
            .as_array()
            .is_some_and(|d| d.iter().any(|v| v == "search_index")),
        "{body}"
    );
    let ours: Vec<&Value> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|i| i["entity_logicalname"] == entity.as_str())
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "only the title match, never the sensitive one: {body}"
    );
    assert_eq!(ours[0]["record_id"], named.to_string());
    assert_eq!(ours[0]["title"], format!("{token} Trading"));
}
