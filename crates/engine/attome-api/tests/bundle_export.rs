//! P-environment-promotion §3 Phase 1 / §6 "Canonical export" — the bundle
//! engine's read-only half against a live, seeded database:
//!
//! - `export_bundle` twice with no intervening change → byte-identical
//!   canonical bytes and the same `bundle_hash`;
//! - the export is a well-formed `attome-bundle/v1` (format string, the
//!   seeded `core` module, the applied schema floor, no empty keys, every
//!   view's query and every lookup target resolvable inside the bundle);
//! - `plan_bundle(export)` against the same database is all-`noop`: zero
//!   retires, zero blocked, `basis_hash == bundle_hash`;
//! - provisioning a new entity + attribute after the export, then planning
//!   the *earlier* bundle, yields exactly one `retire` for that entity when
//!   `allow_retire` is set and one `blocked` ("retire requires allow_retire")
//!   when it is not — the removal-as-soft-retire contract (§4).
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same
//! convention as `sidebar_admin.rs`. The export reads the `is_customized`
//! columns, so the database `DATABASE_URL` names must be migrated through
//! `0132_metadata_is_customized` or later.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-api --test bundle_export -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{
    BUNDLE_FORMAT, PlanAction, PlanOptions, bundle_hash, canonical_json, export_bundle, plan_bundle,
};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;

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
            "approval": {{ "required_actions": [] }}
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

/// A seeded `EngineSystem` over this binary's throwaway database, with every
/// module licensed (so `requires.modules` can never be the thing that
/// blocks a plan here).
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

#[tokio::test]
async fn export_is_deterministic_and_self_plan_is_all_noop() {
    let system = skip_if_no_db!(test_system().await);
    let db = &system.state().base.db;

    let first = export_bundle(db).await.expect("first export");
    let second = export_bundle(db).await.expect("second export");

    // Byte-identical canonical output with no intervening change.
    assert_eq!(canonical_json(&first), canonical_json(&second));
    assert_eq!(bundle_hash(&first), bundle_hash(&second));

    // Well-formed header.
    assert_eq!(first.format, BUNDLE_FORMAT);
    assert!(first.requires.modules.iter().any(|m| m == "core"));
    assert!(
        first.requires.schema_version >= 10,
        "export must run against a database with the v2 baseline migrated (0010); got {}",
        first.requires.schema_version
    );
    assert!(first.requires.platform_version.starts_with(">="));

    // A seeded system has the security entities, privileges, and sidebar.
    assert!(
        first
            .entities
            .iter()
            .any(|e| e.logicalname == "user_account")
    );
    assert!(first.privileges.iter().any(|p| p.key == "system.admin"));
    assert!(!first.sidebar.is_empty(), "sidebar_seed must have run");

    // Identity invariants: no empty keys, every ref resolvable in-bundle.
    for e in &first.entities {
        assert!(!e.logicalname.is_empty());
        for a in &e.attributes {
            assert!(!a.logicalname.is_empty(), "entity {}", e.logicalname);
            if let Some(target) = &a.lookup_entity {
                assert!(
                    first.entities.iter().any(|t| &t.logicalname == target),
                    "lookup {}.{} -> {target} not in bundle",
                    e.logicalname,
                    a.logicalname
                );
            }
        }
    }
    for v in &first.views {
        assert!(
            first.queries.iter().any(|q| q.key() == v.query),
            "view {}.{} names query {:?} which is not in the bundle",
            v.entity,
            v.name,
            v.query
        );
    }
    for s in &first.sidebar {
        assert!(!s.path.is_empty() && s.path.iter().all(|p| !p.is_empty()));
    }

    // Serialized form carries no UUID-shaped value anywhere — identity is
    // logical (§4). A v7 uuid always has "-7" at position 14.
    let text = String::from_utf8(canonical_json(&first)).expect("utf-8");
    let uuid_like = text.as_bytes().windows(36).any(|w| {
        w[8] == b'-'
            && w[13] == b'-'
            && w[18] == b'-'
            && w[23] == b'-'
            && w.iter()
                .enumerate()
                .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
    });
    assert!(!uuid_like, "canonical export must not carry UUIDs");

    // Self-plan: all noop, nothing to retire, nothing blocked.
    let license = system.state().modules.load_full();
    let plan = plan_bundle(db, &license, &first, PlanOptions::default())
        .await
        .expect("plan");
    assert_eq!(plan.basis_hash, bundle_hash(&first));
    assert_eq!(plan.bundle_hash, plan.basis_hash);
    assert!(plan.retires.is_empty(), "{:#?}", plan.retires);
    assert!(plan.blocked.is_empty(), "{:#?}", plan.blocked);
    assert!(
        plan.entries.iter().all(|e| e.action == PlanAction::Noop),
        "{:#?}",
        plan.entries
            .iter()
            .filter(|e| e.action != PlanAction::Noop)
            .collect::<Vec<_>>()
    );
    assert_eq!(plan.summary.creates + plan.summary.updates, 0);
    assert!(plan.summary.noops > 0);
}

#[tokio::test]
async fn object_added_after_export_plans_as_retire_of_the_earlier_bundle() {
    let system = skip_if_no_db!(test_system().await);
    let db = &system.state().base.db;
    let license = system.state().modules.load_full();

    let before = export_bundle(db).await.expect("export before");

    let logicalname = attome_testkit::unique_logicalname("bndl");
    let entity_id = attome_metadata::provision::ensure_entity(
        db,
        &logicalname,
        "Bundle Test",
        Some("name"),
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        db, entity_id, "name", "Name", "text", false, false, true, true, None, None,
    )
    .await
    .expect("provision test attribute");

    // The new entity shows up in a fresh export and as a Create when the
    // fresh export is planned against the earlier one.
    let after = export_bundle(db).await.expect("export after");
    assert_ne!(bundle_hash(&before), bundle_hash(&after));
    assert!(after.entities.iter().any(|e| e.logicalname == logicalname));

    // Planning the EARLIER bundle against live: the entity is live but absent.
    let refused = plan_bundle(db, &license, &before, PlanOptions::default())
        .await
        .expect("plan without allow_retire");
    assert!(refused.retires.is_empty());
    let blocked_for_entity: Vec<_> = refused
        .blocked
        .iter()
        .filter(|e| e.component == "entity" && e.key == logicalname)
        .collect();
    assert_eq!(blocked_for_entity.len(), 1, "{:#?}", refused.blocked);
    assert_eq!(
        blocked_for_entity[0].reason.as_deref(),
        Some("retire requires allow_retire")
    );
    // The entity's attribute goes with its entity and privileges are never
    // retired, so nothing else about this entity may be blocked.
    assert!(
        refused
            .blocked
            .iter()
            .all(|e| e.key == logicalname || !e.key.starts_with(&logicalname)),
        "{:#?}",
        refused.blocked
    );

    let allowed = plan_bundle(
        db,
        &license,
        &before,
        PlanOptions {
            allow_retire: true,
            additive_only: false,
        },
    )
    .await
    .expect("plan with allow_retire");
    assert!(allowed.blocked.is_empty(), "{:#?}", allowed.blocked);
    let retires_for_entity: Vec<_> = allowed
        .retires
        .iter()
        .filter(|e| e.component == "entity" && e.key == logicalname)
        .collect();
    assert_eq!(retires_for_entity.len(), 1, "{:#?}", allowed.retires);
    assert_eq!(retires_for_entity[0].action, PlanAction::Retire);
    // The attribute goes with its entity; it is not listed separately.
    assert!(
        !allowed
            .retires
            .iter()
            .any(|e| e.component == "attribute" && e.key.starts_with(&logicalname)),
        "{:#?}",
        allowed.retires
    );
    // Nothing else changed between the two exports, so every retire must be
    // the test entity itself or (should a later provisioner mint one) a
    // query/view row keyed under it — never an unrelated object.
    for e in &allowed.retires {
        assert!(
            e.key == logicalname || e.key.starts_with(&format!("{logicalname}.")),
            "unexpected retire outside the test entity: {e:#?}"
        );
    }
}
