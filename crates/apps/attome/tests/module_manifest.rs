//! Y4-T1: every engine `attome serve` registers declares a module manifest,
//! and every lookup between two modules' entities is covered by a
//! `depends_on` between them, in either direction (the engine that adds the
//! lookup onto another module's entity is the one that depends). The second
//! test derives the edges from the provisioned metadata, so a new
//! cross-module lookup fails it until a manifest declares the dependency.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis.
//!
//! ```powershell
//! cargo test -p attome --test module_manifest -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeMap, BTreeSet};

use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_core::module_manifest::EngineManifest;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 65536, "request_timeout_secs": 15,
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
                "oauth_google_client_id": "", "oauth_google_client_secret": "",
                "secure_cookies": true
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000 }},
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
            "cors": {{ "allowed_origins": ["{allowed_origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        allowed_origin = ALLOWED_ORIGIN,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Every engine `attome serve` registers, built against the throwaway
/// database; building fails when an engine has no manifest.
async fn system() -> Option<EngineSystem> {
    let mut config = test_config();
    point_config_at(&mut config, &attome_testkit::migrated_db_url()?);
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
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = attome::boot::register_engines(EngineSystem::builder(EngineState::new(base)))
        .build()
        .await
        .expect("every registered engine has a valid manifest");
    Some(system)
}

#[tokio::test]
async fn every_registered_engine_has_a_manifest() {
    let system = skip_if_no_db!(system().await);
    let manifests = &system.state().engine_manifests;
    let engines: BTreeSet<&str> = manifests.iter().map(|m| m.engine).collect();
    assert_eq!(engines.len(), manifests.len(), "engine names are unique");
    for name in [
        "attome-security",
        "attome-sales",
        "attome-service",
        "attome-ai",
    ] {
        assert!(
            engines.contains(name),
            "{name} is registered with a manifest"
        );
    }
    for manifest in manifests.iter() {
        manifest.check().expect("each manifest checks");
    }
}

#[tokio::test]
async fn manifests_declare_every_cross_module_lookup() {
    let system = skip_if_no_db!(system().await);
    let manifests: &Vec<EngineManifest> = &system.state().engine_manifests;
    // entity -> the module of the engine that owns it.
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    for manifest in manifests.iter() {
        for entity in manifest.entities {
            owner.insert(entity, manifest.module);
        }
    }
    let lookups: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.logicalname::text, t.logicalname::text            FROM attribute_info a            JOIN entity_info e ON e.id = a.entity_ref            JOIN entity_info t ON t.id = a.lookup_entity_ref           WHERE a.lookup_entity_ref IS NOT NULL             AND (a.is_active IS NULL OR a.is_active = true)",
    )
    .fetch_all(&system.state().base.db)
    .await
    .unwrap();
    let mut missing: BTreeSet<String> = BTreeSet::new();
    for (from, to) in &lookups {
        let (Some(from_module), Some(to_module)) =
            (owner.get(from.as_str()), owner.get(to.as_str()))
        else {
            continue;
        };
        if from_module == to_module || *to_module == "core" || *from_module == "core" {
            continue;
        }
        // The engine that adds a cross-module lookup is the one that
        // depends: GRC adds `risk_ref` onto project's `project_issue`, so
        // the edge runs project -> grc while grc depends on project.
        let declares = |module: &str, on: &str| {
            manifests
                .iter()
                .filter(|m| m.module == module)
                .any(|m| m.depends_on.contains(&on))
        };
        let declared = declares(from_module, to_module) || declares(to_module, from_module);
        if !declared {
            missing.insert(format!(
                "{from_module} -> {to_module} ({from}.* looks up {to})"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "modules whose entities look up another module's, without depends_on:
{}",
        missing.into_iter().collect::<Vec<_>>().join(
            "
"
        )
    );
}

/// The configuration boot refuses and Module Management answers 422 for
/// (`PUT /api/v1/admin/license/modules` runs this same check): GRC on with
/// Project off, with the real manifests.
#[tokio::test]
async fn grc_without_project_is_refused() {
    let system = skip_if_no_db!(system().await);
    let manifests = &system.state().engine_manifests;
    let mut bits = attome_modules::ModuleSet::all().bits();
    bits[attome_modules::MODULE_PROJECT.word] &= !attome_modules::MODULE_PROJECT.mask;
    // Service needs Project too; off, so GRC's dependency is the one refused.
    bits[attome_modules::MODULE_SERVICE.word] &= !attome_modules::MODULE_SERVICE.mask;
    let err = attome_core::module_manifest::check_dependencies(
        manifests,
        &attome_modules::ModuleSet::from_bits(bits),
    )
    .unwrap_err();
    assert!(err.contains("grc") && err.contains("project"), "{err}");
    attome_core::module_manifest::check_dependencies(manifests, &attome_modules::ModuleSet::all())
        .expect("every module on is a valid configuration");
}
