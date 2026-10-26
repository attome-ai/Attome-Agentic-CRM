//! E13-T13: the search-optimisation work end to end against a real
//! database: with every SEO flag off a publish does no SEO work; a page
//! whose path changes keeps answering at the old path; and the SEO tables
//! hold no personal data, so erasing an author never needs to reach them.
//!
//! Fixture rows are direct SQL against this binary's throwaway database
//! (guidelines §4's test exemption). The Arabic link-preview check is
//! manual: `docs/content/seo-arabic-preview-check.md`.
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-content --test seo_e2e"
//! ```

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use attome_config::AppConfig;
use attome_content::model::PageDetail;
use attome_content::redirect::{encode_path, record_path_change, resolve};
use attome_content::render_html::{Site, render_version_in_tx};
use attome_content::seo::audit::{AuditInputs, audit_after_save, audit_page, run_nightly};
use attome_content::seo::console::ping_after_publish;
use attome_content::seo::settings::PageSeo;
use attome_content::versions::record_version_in_tx;
use attome_core::EngineState;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

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
                "host": "localhost", "port": 5555, "dbname": "unused",
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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
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
            "cors": {{ "allowed_origins": ["http://allowed.test"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

// `std::env::set_var` is unsafe in edition 2024 (concurrent mutation from
// another thread is a real data race) — same `ENV_LOCK` shape `attome-workflow/
// tests/execution.rs` uses, serializing this suite's own writes against each
// other regardless of `--test-threads`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
    // reads this var while this guard is held.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
    }
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
    Some(EngineState::new(base))
}

fn ctx() -> SecurityContext {
    SecurityContext {
        user_id: Uuid::now_v7(),
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

/// A space with a domain, so the only thing between a publish and an
/// IndexNow submission is the flag.
async fn space(db: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_space (id, name, created_by, updated_by, owner_layer, domain) \
         VALUES ($1, $2, $3, $3, 'project', $4)",
    )
    .bind(id)
    .bind(format!("SEO E2E Space {id}"))
    .bind(Uuid::now_v7())
    .bind(format!("seo-{}.example", id.simple()))
    .execute(db)
    .await
    .expect("insert content_space");
    id
}

/// A published public page whose content would draw audit findings (no
/// search title or description, a heading-less body) if the audit ran.
async fn published_page(db: &PgPool, space: Uuid, path: &str) -> Uuid {
    let id = Uuid::now_v7();
    let blocks = json!([
        {"id": Uuid::now_v7(), "kind": "rich_text", "props": {"html": "<p>Short.</p>"}},
        {"id": Uuid::now_v7(), "kind": "image", "props": {"src": "https://example.com/a.png"}}
    ]);
    sqlx::query(
        "INSERT INTO content_page \
            (id, content_space_id, title, url_path, status, blocks_draft, blocks_published, \
             created_by, updated_by, audience, published_at) \
         VALUES ($1, $2, $3, $4, 'published', $5, $5, $6, $6, 'public', now())",
    )
    .bind(id)
    .bind(space)
    .bind(format!("SEO E2E Page {id}"))
    .bind(path)
    .bind(&blocks)
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("insert content_page");
    // Publish the way the admin publish does: a version, rendered.
    let mut tx = db.begin().await.expect("begin");
    let version = record_version_in_tx(&mut tx, id, Uuid::now_v7(), None)
        .await
        .expect("version");
    render_version_in_tx(
        &mut tx,
        id,
        version,
        &Site {
            base_url: "https://site.example".into(),
        },
    )
    .await
    .expect("render");
    tx.commit().await.expect("commit");
    id
}

async fn load(db: &PgPool, id: Uuid) -> PageDetail {
    let (title, url_path, blocks): (String, String, Value) =
        sqlx::query_as("SELECT title, url_path, blocks_published FROM content_page WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("read page");
    serde_json::from_value(json!({
        "id": id,
        "parent_page_id": null,
        "content_space_id": Uuid::nil(),
        "title": title,
        "url_path": url_path,
        "status": "published",
        "template_id": null,
        "blocks_draft": blocks,
        "blocks_published": blocks,
        "seo_title": null,
        "seo_description": null,
        "published_at": chrono::Utc::now(),
        "publish_at": null,
        "unpublish_at": null,
        "row_version": 1,
        "created_at": chrono::Utc::now(),
        "updated_at": chrono::Utc::now(),
    }))
    .expect("a page")
}

/// Every SEO flag off (the default): publishing a page and running the
/// save hook, the publish hook and the nightly audit leave no finding, no
/// score and no queued IndexNow job.
// feature: E13
#[tokio::test]
async fn publish_with_flags_off_does_no_seo_work() {
    let state = skip_if_no_db!(test_state().await);
    let db = state.base.db.clone();
    let flags = state.feature_flags();
    for flag in [
        "content.seo_audit",
        "content.seo_clusters",
        "content.search_console",
        "content.instant_indexing",
        "content.seo_arabic_paths",
        "content.seo_agent",
    ] {
        assert!(!flags.is_on_for_deployment(flag), "{flag} must default off");
        assert!(!flags.is_on(flag, &ctx()).await, "{flag} must default off");
    }

    let space = space(&db).await;
    let id = published_page(&db, space, &format!("/seo-off-{}", Uuid::now_v7().simple())).await;
    let page = load(&db, id).await;
    // The page has problems the audit would report.
    assert!(!audit_page(&page, &PageSeo::default(), &AuditInputs::default()).is_empty());

    audit_after_save(&state, &ctx(), &page).await;
    ping_after_publish(&state, id).await;
    assert_eq!(run_nightly(&state).await.expect("nightly"), 0);

    let findings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM content_seo_finding WHERE page_ref = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("count findings");
    assert_eq!(findings, 0);
    let (score, audited): (Option<i16>, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT seo_score, seo_audited_at FROM content_page WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("read score");
    assert_eq!((score, audited), (None, None));
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'",
    )
    .bind(format!("seo-{}.example", space.simple()))
    .fetch_one(&db)
    .await
    .expect("count jobs");
    assert_eq!(queued, 0, "no IndexNow job is queued while the flag is off");
}

/// A page whose path changes still answers at the old path: the public
/// view's lookup finds the redirect, and the target it sends is the new
/// path percent-encoded (an Arabic path travels as ASCII).
// feature: E13
#[tokio::test]
async fn path_change_keeps_old_url_working() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(3).await);
    let space = space(&db).await;
    let tag = Uuid::now_v7().simple().to_string();
    let old = format!("/pricing-{tag}");
    let new = format!("/الأسعار-{tag}");
    let id = published_page(&db, space, &old).await;

    let mut tx = db.begin().await.expect("begin");
    sqlx::query("UPDATE content_page SET url_path = $2 WHERE id = $1")
        .bind(id)
        .bind(&new)
        .execute(&mut *tx)
        .await
        .expect("move page");
    record_path_change(&mut tx, id, &old, &new)
        .await
        .expect("record redirect");
    tx.commit().await.expect("commit");

    let public = vec!["public".to_string()];
    let (to_space, to_path) = resolve(&db, &old, &public)
        .await
        .expect("resolve")
        .expect("the old path redirects");
    assert_eq!((to_space, to_path.as_str()), (space, new.as_str()));
    let encoded = encode_path(&to_path);
    assert!(encoded.is_ascii(), "{encoded}");
    assert_eq!(
        encoded,
        format!("/%D8%A7%D9%84%D8%A3%D8%B3%D8%B9%D8%A7%D8%B1-{tag}")
    );
    // The new path is the page itself, not a redirect.
    assert_eq!(resolve(&db, &new, &public).await.expect("resolve"), None);
}

/// The SEO tables hold no personal data, so erasing an author touches
/// none of them: their columns are exactly these, and the only one naming
/// a person is the robots body's `updated_by`. A new column fails here
/// until someone decides whether erasure must reach it.
// feature: E13
#[tokio::test]
async fn erasure_of_author_does_not_touch_seo_tables() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(3).await);
    let expected: &[(&str, &[&str])] = &[
        (
            "content_seo_finding",
            &[
                "block_ref",
                "created_at",
                "detail",
                "id",
                "page_ref",
                "rule",
                "severity",
            ],
        ),
        (
            "content_seo_topic",
            &[
                "created_at",
                "id",
                "language",
                "name",
                "pillar_page_ref",
                "row_version",
                "updated_at",
            ],
        ),
        ("content_seo_topic_page", &["page_ref", "topic_ref"]),
        (
            "content_search_stat",
            &[
                "avg_position",
                "clicks",
                "impressions",
                "page_ref",
                "source",
                "stat_date",
                "top_queries",
            ],
        ),
        (
            "content_site_robots",
            &[
                "body",
                "row_version",
                "site_key",
                "updated_at",
                "updated_by",
            ],
        ),
        (
            "content_sitemap",
            &["built_at", "lang", "part", "site_key", "xml"],
        ),
        (
            "content_page_redirect",
            &["created_at", "old_path", "page_id"],
        ),
    ];
    for (table, columns) in expected {
        let found: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.columns \
              WHERE table_schema = current_schema() AND table_name = $1 \
              ORDER BY column_name",
        )
        .bind(table)
        .fetch_all(&db)
        .await
        .expect("read columns");
        assert_eq!(found, *columns, "{table}");
        let people: Vec<&str> = found
            .iter()
            .map(String::as_str)
            .filter(|c| {
                c.ends_with("_by")
                    || c.contains("user")
                    || c.contains("email")
                    || c.contains("author")
                    || c.contains("owner")
            })
            .collect();
        let allowed: &[&str] = if *table == "content_site_robots" {
            &["updated_by"]
        } else {
            &[]
        };
        assert_eq!(people, allowed, "{table}");
    }
}
