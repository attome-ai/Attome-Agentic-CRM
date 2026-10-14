//! D-534 regression — record-set lookup values that name their target by
//! business key, and the 2026-09-15 shared-dev boot failure that motivated
//! them.
//!
//! That boot died applying a record set whose lookup value was the
//! precomputed `derived_id` literal of a seeded row, but the dev database's
//! copy of that row predated derived ids, so the literal matched nothing and
//! the create failed lookup validation. A record set can now name the target
//! by key; this suite reproduces that database state and proves the failure,
//! the fix, and idempotent re-planning.
//!
//! The lookup used here is `ai_model.provider_ref` -> `ai_provider`,
//! applied from the shipped `attome-ai-model-catalog-data` row with its
//! `provider_ref` replaced. (The scenario originally used the AI provider's
//! `authentication_type_ref`, removed from that entity.)
//!
//! Its own test binary on purpose: the scenario rewrites the "Example
//! Provider" row's id, which `platform_bundle_apply.rs`'s fresh-database
//! scaffold test (a different binary, so a different D-343 clone) must never
//! observe.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test bundle_record_key_reference -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{
    Bundle, PlanAction, PlanOptions, apply_platform_bundle, derived_id, plan_bundle,
};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// An id no derived-id scheme would produce — what a seeded row created
/// before derived ids existed (the shared dev database, 2026-09-15) carries.
const DEV_PROVIDER_ID: &str = "01a08fc8-9a40-740d-839e-63b354325dee";

const MODEL_DATA: &str =
    include_str!("../../../../platform-bundles/attome-ai-model-catalog-data.json");

/// Every bundle the model scaffold depends on, in `boot.rs`'s order, up to
/// and including the `attome-ai-model-catalog` schema bundle.
const PREREQUISITES: &[(&str, &str)] = &[
    (
        "attome-ai-provider",
        include_str!("../../../../platform-bundles/attome-ai-provider.json"),
    ),
    (
        "attome-ai-provider-data",
        include_str!("../../../../platform-bundles/attome-ai-provider-data.json"),
    ),
    (
        "attome-ai-model-catalog",
        include_str!("../../../../platform-bundles/attome-ai-model-catalog.json"),
    ),
];

/// The pieces of the throwaway database's URL the config's own `database.*`
/// fields must agree with — `bundle::apply` opens a fresh migrator
/// connection from `config.database` when it provisions an indexed
/// attribute (same reason as `platform_bundle_apply.rs`'s `DbParts`).
struct DbParts {
    host: String,
    port: String,
    name: String,
    user: String,
    password: String,
}

fn db_parts() -> DbParts {
    let url = attome_testkit::migrated_db_url().expect("test_system checks DATABASE_URL first");
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .expect("postgres:// DATABASE_URL");
    let (userinfo, rest) = rest.split_once('@').expect("user@host in DATABASE_URL");
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (hostport, rest) = rest.split_once('/').expect("host/db in DATABASE_URL");
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "5432"));
    let name = rest.split('?').next().unwrap_or(rest);
    DbParts {
        host: host.to_owned(),
        port: port.to_owned(),
        name: name.to_owned(),
        user: user.to_owned(),
        password: password.to_owned(),
    }
}

fn test_config() -> AppConfig {
    let db = db_parts();
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 16777216, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 9, "connection_pool_size": 4, "timeout": 2000,
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        db_host = db.host,
        db_port = db.port,
        db_name = db.name,
        db_user = db.user,
        db_password = db.password,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
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

async fn apply_prerequisites(state: &EngineState) {
    for (name, bytes) in PREREQUISITES {
        apply_platform_bundle(state, name, bytes)
            .await
            .unwrap_or_else(|e| panic!("{name} applies: {e:?}"));
    }
}

/// `attome-ai-model-catalog-data.json` with its one row's `provider_ref`
/// replaced, serialized back to bundle JSON.
fn model_data_with_provider_ref(provider_ref: Value, row_name: &str) -> String {
    let mut bundle: Value = serde_json::from_str(MODEL_DATA).expect("model data is JSON");
    let row = &mut bundle["record_sets"][0]["rows"][0];
    row["provider_ref"] = provider_ref;
    row["name"] = json!(row_name);
    serde_json::to_string(&bundle).expect("serialize bundle")
}

async fn model_count(state: &EngineState, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM ai_model WHERE name = $1")
        .bind(name)
        .fetch_one(&state.base.db)
        .await
        .expect("count models")
}

#[tokio::test]
async fn model_seed_resolves_a_provider_row_that_predates_derived_ids() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    apply_prerequisites(state).await;

    // Reproduce the shared dev database: "Example Provider" exists, but under
    // the id it was created with before derived ids, not the derived one.
    // Throwaway database; nothing references the row yet.
    let derived_provider = derived_id("record", "ai_provider[name=Example Provider]");
    let dev_provider: Uuid = DEV_PROVIDER_ID.parse().expect("uuid");
    assert_ne!(
        dev_provider, derived_provider,
        "the scenario needs an id other than the derived one"
    );
    let moved = sqlx::query(
        "UPDATE ai_provider SET id = $1 WHERE name = 'Example Provider' AND is_active = true",
    )
    .bind(dev_provider)
    .execute(&state.base.db)
    .await
    .expect("move Example Provider to the dev id");
    assert_eq!(
        moved.rows_affected(),
        1,
        "exactly one active Example Provider row"
    );

    // The exact 2026-09-15 failure: the derived-id literal names no live row.
    let old = model_data_with_provider_ref(json!(derived_provider.to_string()), "Example Model");
    let error = apply_platform_bundle(state, "regression-model-data-old-literal", &old)
        .await
        .expect_err("a derived-id literal must not resolve against a pre-existing provider");
    let message = format!("{error:?}");
    assert!(
        message.contains("provider_ref: lookup target does not exist"),
        "{message}"
    );
    assert_eq!(model_count(state, "Example Model").await, 0);

    // Naming the provider by key resolves the live row and applies.
    let by_key = model_data_with_provider_ref(
        json!({"key": {"name": "Example Provider"}}),
        "Example Model",
    );
    apply_platform_bundle(state, "regression-model-data-by-key", &by_key)
        .await
        .unwrap_or_else(|e| panic!("model data by key applies: {e:?}"));
    let provider_ref: Uuid =
        sqlx::query_scalar("SELECT provider_ref FROM ai_model WHERE name = 'Example Model'")
            .fetch_one(&state.base.db)
            .await
            .expect("Example Model row exists");
    assert_eq!(provider_ref, dev_provider, "resolves the live provider row");

    // Idempotent: re-planning the same bundle (bypassing the watermark, which
    // would short-circuit before planning) compares the resolved id, so the
    // existing row is a no-op, not an update.
    let bundle: Bundle = serde_json::from_str(&by_key).expect("parse model data");
    let license = state.modules.load_full();
    let plan = plan_bundle(
        &state.base.db,
        &license,
        &bundle,
        PlanOptions {
            allow_retire: false,
            additive_only: true,
        },
    )
    .await
    .expect("re-plan model data");
    assert!(plan.blocked.is_empty(), "{:#?}", plan.blocked);
    assert!(
        plan.entries.iter().all(|e| e.action == PlanAction::Noop),
        "{:#?}",
        plan.entries
    );
    apply_platform_bundle(state, "regression-model-data-reapply", &by_key)
        .await
        .unwrap_or_else(|e| panic!("re-applying model data is a no-op: {e:?}"));
    assert_eq!(model_count(state, "Example Model").await, 1);
}

#[tokio::test]
async fn an_unresolvable_key_reference_blocks_the_plan_without_writing() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    apply_prerequisites(state).await;

    let unresolvable = model_data_with_provider_ref(
        json!({"key": {"name": "No Such Provider"}}),
        "Unresolvable Model",
    );
    let error = apply_platform_bundle(state, "regression-model-data-unresolvable", &unresolvable)
        .await
        .expect_err("a key matching no live row must block");
    let message = format!("{error:?}");
    assert!(
        message.contains("provider_ref: no active ai_provider row matches name=No Such Provider"),
        "{message}"
    );
    assert_eq!(model_count(state, "Unresolvable Model").await, 0);

    let malformed = model_data_with_provider_ref(
        json!({"key": {"name": "Example Provider"}, "extra": true}),
        "Malformed Reference Model",
    );
    let error = apply_platform_bundle(state, "regression-model-data-malformed", &malformed)
        .await
        .expect_err("a malformed key reference must block, not be written as-is");
    assert!(
        format!("{error:?}").contains("provider_ref: a key reference must be"),
        "{error:?}"
    );
    assert_eq!(model_count(state, "Malformed Reference Model").await, 0);
}
