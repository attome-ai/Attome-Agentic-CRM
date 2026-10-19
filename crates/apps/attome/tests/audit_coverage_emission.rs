//! Audit 10/10 plan item 3.8 (contract C3, D-542 rule 4): every route whose
//! `x-audit` extension in the committed `openapi.json` declares a mandatory
//! event actually writes it.
//!
//! Every mutating route must *declare* its event (D-542; a review rule since
//! D-768 removed the coverage script); this test proves the event is *written*. It
//! reads `openapi.json`, selects every operation whose `x-audit.policy` is
//! `mandatory`, drives each one through the full middleware stack against a
//! throwaway database, and asserts the declared primary event row appeared
//! (in `audit_ingest` on the chainer path, or `audit_header` on the
//! synchronous one).
//!
//! A mapped route with no driver in [`drive`] fails the test, so a new
//! mandatory mapping cannot land without its emission proof. The only routes
//! excused are listed in [`UNDRIVABLE`], each with the reason; the test fails
//! if an entry there stops being a mapped mandatory route.
//!
//! A second test, `failed_second_factor_attempts_are_audited`, covers the
//! failure-path event (`Security` + `FailedLogin`) that the route drivers,
//! which all succeed, cannot reach.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p server --test audit_coverage_emission -- --test-threads=1
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

use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_audit::security::SecurityAuditor;
use attome_audit::{AuditCategory, AuditOperation};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "audit-emission-password-1";

/// Mapped mandatory routes this test cannot drive to success, with the
/// reason. Each must still be a mapped mandatory route (checked), so the list
/// cannot silently outlive its route.
const UNDRIVABLE: &[(&str, &str)] = &[
    (
        "POST /api/v1/einvoice/devices",
        "needs e-invoicing on and the billing pack's seller settings, which this harness does not set; attome-testapp's einvoice_devices test drives it and its Credential event",
    ),
    (
        "POST /api/v1/einvoice/devices/{id}/onboard",
        "calls ZATCA; attome-testapp's einvoice_devices test drives onboarding through recorded answers and checks its Credential events",
    ),
    (
        "POST /api/v1/contract/counterparty-match/run",
        "needs the contract pack's contract entity, which this harness does not install (the route answers 404);          attome-testapp's contract_counterparty test drives the run and its Configuration event",
    ),
    (
        "POST /api/v1/commission/plans/{id}/publish",
        "needs the commission pack's plan, version and component entities, which this harness does not install",
    ),
    (
        "POST /api/v1/sales/opportunities/{id}/change-owner",
        "needs the crm and sales packs' opportunity and team entities, which this harness does not install",
    ),
    (
        "POST /api/v1/sales/opportunities/{id}/team/copy-account-team",
        "needs the crm and sales packs' account team and opportunity entities, which this harness does not install",
    ),
    (
        "POST /api/v1/sales/opportunities/{id}/team",
        "needs the sales pack's opportunity and team entities, which this harness does not install; \
         the member's share and its Access event are written in one transaction by attome-sales's team.rs",
    ),
    (
        "PATCH /api/v1/sales/opportunities/{id}/team/{member_id}",
        "needs the sales pack's opportunity and team entities, which this harness does not install",
    ),
    (
        "DELETE /api/v1/sales/opportunities/{id}/team/{member_id}",
        "needs the sales pack's opportunity and team entities, which this harness does not install",
    ),
    (
        "PUT /api/v1/admin/env-variables/{name}",
        "needs a published environment_variable definition; attome-api's model_admin.rs environment_variable_values_are_set_per_deployment defines, publishes and sets one, and the clear driver below audits the same Configuration path",
    ),
    (
        "POST /api/v1/admin/mcp-servers/{id}/import",
        "calls the registered MCP server's tools/list, and this harness runs no MCP \
         server; the import's own event is written in the same transaction as the tool \
         rows, after the call, through the same audit_event helper the create and \
         set-tool drivers below audit",
    ),
    (
        "POST /api/v1/admin/model/import",
        "imports a set of model files as drafts; attome-api's model_admin.rs \
         export_then_import_keeps_content_hashes drives it end to end, and each draft \
         it saves goes through the same model_edit path the commands driver below audits",
    ),
    (
        "POST /api/v1/admin/model/blueprint/apply",
        "needs a whole blueprint file set; attome-api's model_admin.rs \
         a_blueprint_plans_applies_and_rolls_back drives apply and rollback end to end",
    ),
    (
        "POST /api/v1/admin/model/blueprint/rollback",
        "rolls back an applied blueprint; driven with apply by attome-api's model_admin.rs \
         a_blueprint_plans_applies_and_rolls_back",
    ),
    (
        "POST /api/v1/a2a/agents/{agent}/tasks",
        "runs a model turn, and this harness has no inference endpoint, so the response \
         depends on how the turn fails; the task's mandatory event is the session start \
         `agent::start_session_from_object` writes, which the \
         POST /api/v1/model/agents/{agent}/sessions driver audits",
    ),
    (
        "POST /api/v1/s2s/webportals/{keyword}/login",
        "S2S-only: needs an HMAC-signed request from a client granted \
         webportal.trusted_login (this driver sends staff sessions); \
         portal_auth.rs d779_a_trusted_server_creates_and_signs_in_players drives it \
         with a real signed request and checks its security events",
    ),
    (
        "POST /api/v1/s2s/webportals/{keyword}/accounts/{user_id}/email",
        "S2S-only like the trusted login (D-780); portal_auth.rs \
         d780_an_email_is_added_only_once_its_link_is_opened drives it with real signed requests",
    ),
    (
        "POST /api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/enroll",
        "S2S-only like the trusted login (D-780); portal_auth.rs \
         d780_mfa_is_turned_on_and_off_and_asked_for_at_sign_in drives it with real signed requests",
    ),
    (
        "POST /api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/confirm",
        "S2S-only like the trusted login (D-780); portal_auth.rs \
         d780_mfa_is_turned_on_and_off_and_asked_for_at_sign_in drives it with real signed requests",
    ),
    (
        "POST /api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/disable",
        "S2S-only like the trusted login (D-780); portal_auth.rs \
         d780_mfa_is_turned_on_and_off_and_asked_for_at_sign_in drives it with real signed requests",
    ),
    (
        "GET /{keyword}/api/v1/auth/oidc/{provider}/callback",
        "needs an authorization code from a live OIDC provider for the portal's \
         configured issuer; the sign-in it completes writes its event through the same \
         `auth::federated_session` tail the OIDC link and MFA drivers exercise",
    ),
    (
        "POST /api/v1/admin/themes/{id}/assets",
        "writes the file to the object store before the event is written; this \
         harness's storage config is a placeholder with no live bucket \
         (attome-core theme_store's check_asset tests cover what is refused first)",
    ),
    (
        "POST /api/v1/admin/archive/records/{id}/restore",
        "needs an archived record whose payload sits in the object store; this \
         harness's storage config is a placeholder with no live bucket \
         (crates/engine/attome-api/tests/side_path_atomicity.rs covers the event)",
    ),
    (
        "POST /api/v1/admin/dsr/requests/{id}/fulfill-access",
        "streams the export to the object store before the event is written; this \
         harness's storage config is a placeholder with no live bucket \
         (crates/engine/attome-api/tests/dsr_admin.rs runs it against a live store)",
    ),
    (
        "POST /api/v1/admin/webportals/{id}/users/{user_id}/export",
        "the G-14 portal data export is fulfill-access (`record_and_fulfill_access`): it \
         streams to the object store before the event is written, and this harness has no \
         live bucket (crates/server/tests/portal_isolation.rs `g14_…` runs it against one)",
    ),
    (
        "POST /api/v1/admin/dsr/requests/{id}/fulfill-portability",
        "same export path as fulfill-access: streams to the object store before the \
         event is written, and this harness has no live bucket",
    ),
    (
        "POST /api/v1/auth/google",
        "needs a Google ID token that verifies against Google's JWKS; the event is \
         written by the same `session::issue_session_cookies_for` login hook the \
         password login uses",
    ),
    (
        "POST /api/v1/auth/step-up/{operation}/google",
        "needs a Google ID token that verifies against Google's JWKS; the event is \
         written by `account_event_hook` inside `step_up::complete_google_step_up_with`'s \
         elevation, the same hook the local verify driver below exercises",
    ),
    (
        "POST /api/v1/auth/identity-link/google",
        "needs a Google ID token that verifies against Google's JWKS; the event is \
         written by `account_event_hook` inside `link_google_to_user_with`, the same \
         hook shape `before_commit_hook.rs` and the admin identity-link driver prove",
    ),
    (
        "GET /api/v1/auth/oidc/{provider}/callback",
        "needs a live OpenID provider (crates/server/tests/keycloak_oidc.rs runs \
         against Keycloak when available); same `session::issue_session_cookies_for` \
         login hook",
    ),
    (
        "DELETE /api/v1/me/mail-connections/{provider}",
        "an attome-integration route, and this harness answers attome-integration          routes 404 (the undiagnosed gap noted for the systems/{id}/credential entry          below)",
    ),
    (
        "POST /api/v1/admin/integrations/systems/{id}/credential",
        "the create_system prerequisite 404s (FeatureHidden) in this harness even \
         with full_license() (all module bits set) and \
         `.register(attome_integration::IntegrationModel)`, unlike three other \
         registered models (attome-process/attome-predict/attome-state) that work \
         the same way — the specific cause is undiagnosed, not a license or route \
         string mismatch (both verified character-for-character)",
    ),
    (
        "POST /api/v1/admin/retention/actions/{id}/approve",
        "retention.dry_run defaults true (attome-config's default_retention_dry_run) \
         and this harness's test_config() does not override it, so \
         do_approve_retention_action's own dry_run guard always refuses; reject \
         (no dry_run check) drives the same transaction/event shape",
    ),
    (
        "POST /api/v1/work-request/{id}/convert-to-ticket",
        "service_work_request/service_ticket are seeded platform-bundle \
         entities boot.rs provisions, which EngineSystem::builder(...).build() (unlike \
         full boot) does not — this DB-focused harness has no equivalent seed",
    ),
    (
        "POST /api/v1/consents/confirm",
        "a form post carrying a token that only a double opt-in email holds (the \
         token is stored hashed); the confirmation's consent event and security \
         event are written by the same code path as the capture's",
    ),
    (
        "POST /api/v1/service-offering/{id}/publish",
        "service_offering/service_offering_version are seeded platform-bundle entities \
         boot.rs provisions, which this DB-focused harness does not (same gap as \
         convert-to-ticket)",
    ),
    (
        "POST /api/v1/work-request/{id}/convert",
        "same gap as convert-to-ticket, plus a service_conversion_map, also a seeded \
         platform-bundle entity this harness does not provision",
    ),
    (
        "POST /api/v1/work-request/{id}/convert-to-task",
        "same gap as convert-to-ticket, plus project_work_item is also a \
         seeded platform-bundle entity this harness does not provision",
    ),
    (
        "POST /api/v1/admin/metadata/changesets/adopt",
        "adopt is refused unless metadata.changesets.mode = \"required\" (development \
         authoring), and this harness runs `auto` so every other metadata driver records \
         without an open changeset; crates/engine/attome-api/tests/changeset_replay.rs \
         `every_admin_change_yields_exactly_one_op_in_order` adopts a real closed changeset \
         in required mode and checks its Configuration/Import event",
    ),
    (
        "POST /api/v1/work-request/{id}/convert-to-project",
        "same gap as convert-to-ticket, plus attome_project is also a seeded \
         platform-bundle entity this harness does not provision",
    ),
];

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 65536, "request_timeout_secs": 30,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 10, "timeout": 5.0
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
            "rate_limit": {{ "anonymous_rpm": 100000, "authenticated_rpm": 100000 }},
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
            "s2s": {{ "enabled": false, "key_encryption_key": "{s2s_key}" }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["{origin}"] }},
            "events": {{ "webhooks_enabled": true, "webhook_signing_key": "{webhook_key}" }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        s2s_key = "cd".repeat(32),
        webhook_key = "ef".repeat(32),
        origin = ORIGIN,
    );
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    config.auth.mfa_policy = "optional".into();
    config.auth.mfa_encryption_key = KeyRing::single("ab".repeat(32));
    // The reset-request route only issues (and audits) a token when email is on.
    config.email.enabled = true;
    // The register route only creates (and audits) an account in public mode.
    config.auth.registration_mode = "public".into();
    // D-566 — the AI provider credential route encrypts under this ring and
    // refuses outright when it has no active key, so the driver would never
    // reach the audited write without it.
    config.inference.provider_credential_key = KeyRing::single("ef".repeat(32));
    // D-788 rule 9 — the recovery-archive restore drivers seal and open
    // values under this ring (a restore without it is `archive_key_missing`).
    config.metadata.recovery_archive_key_encryption_key = KeyRing::single("12".repeat(32));
    // C4 — the chat confirm driver executes an AI-surface action, which
    // `gate::admissible` refuses while the AI switch is off (it is fixed at
    // process start, A-18), so this process starts with it on.
    config.inference.ai = attome_config::AiEnablement {
        enabled: true,
        fields: true,
        chat: true,
        semantic_search: true,
        workflow_nodes: true,
    };
    config
}

fn full_license() -> std::sync::Arc<attome_modules::ModuleSet> {
    std::sync::Arc::new(attome_modules::ModuleSet::from_bits([u64::MAX; 4]))
}

/// Everything a driver needs: the assembled app, state, and an administrator.
struct Fx {
    app: axum::Router,
    xrm: EngineState,
    base: AppState,
    admin_id: Uuid,
    admin_token: String,
    /// A throwaway entity with an owner, a filterable `title` field and one
    /// record, for the share, owner and condition routes.
    entity: String,
    entity_id: Uuid,
    record_id: Uuid,
}

async fn fixture() -> Option<Fx> {
    let mut config = test_config();
    let throwaway_url = attome_testkit::migrated_db_url()?;
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
    let base = AppState::new(
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    // Views, sidebar, stored queries, approvals, audit search/export, DSR,
    // erasure, rewrap and the dashboard reconciliations are core routes;
    // `/agents/{id}/sessions` and `/mcp` are mounted by `ActionModel`.
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .register(attome_ai::ActionModel)
        // D-576 — `/api/v1/admin/webportals/…`.
        .register(attome_portal::PortalModel)
        .register(attome_state::StateModel)
        .register(attome_workflow::WorkflowModel)
        .register(attome_process::ProcessModel)
        .register(attome_predict::PredictModel)
        // D-786: `POST /api/v1/metrics/{id}/compute` is a mandatory mapping.
        .register(attome_metric::MetricModel)
        .build()
        .await
        .expect("build EngineSystem");
    system.state().modules.store(full_license());

    let xrm = system.state().clone();
    let base_state = xrm.base.clone();
    let license = xrm.modules.clone();
    let public_bundle = attome_server::RouteBundle::new(
        auth::public_routes(license, SecurityAuditor::from_state(&xrm))
            .with_state(base_state.clone()),
    );
    let protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(SecurityAuditor::from_state(&xrm)).with_state(base_state.clone()),
    );
    // D-573 — the portal's own routes, mounted exactly as `main.rs` mounts them.
    let portal_bundle = attome_server::RouteBundle::new(attome_portal::router::app(xrm.clone()));
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .add_audience_bundle(portal_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    let (admin_id, _) = seed_user(&base_state, "admin").await;
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(&base_state.db)
            .await
            .expect("system.admin is seeded by attome_security::seed");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(admin_id)
    .bind(privilege_id)
    .execute(&base_state.db)
    .await
    .expect("grant system.admin");
    let admin_token = session_token(&base_state, admin_id, true).await;

    let mut fx = Fx {
        app,
        xrm,
        base: base_state,
        admin_id,
        admin_token,
        entity: format!("emission_{}", Uuid::now_v7().simple()),
        entity_id: Uuid::nil(),
        record_id: Uuid::nil(),
    };
    // Before the throwaway entity: its registry swap picks these up too.
    provision_agent_entities(&fx.base.db).await;
    let (entity_id, record_id) = provision_entity_and_record(&fx).await;
    fx.entity_id = entity_id;
    fx.record_id = record_id;
    Some(fx)
}

/// `ai_model`, `ai_agent` and `ai_agent_policy` with just the
/// columns `attome_ai::agent::start_session` reads. Boot applies their platform
/// bundles from `crates/server/src/boot.rs`, which `EngineSystem::build` does not;
/// same provisioning as `crates/engine/attome-ai/tests/agent_session_governance.rs`.
async fn provision_agent_entities(db: &attome_db::DbPool) {
    // Once per binary: every test here shares one throwaway database, and two
    // fixtures reconciling the same entity concurrently would race.
    static PROVISIONED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    PROVISIONED
        .get_or_init(|| provision_agent_entities_once(db))
        .await;
}

async fn provision_agent_entities_once(db: &attome_db::DbPool) {
    use attome_metadata::provision::{ensure_attribute, ensure_entity};

    let model = ensure_entity(db, "ai_model", "AI Model", Some("name"), false)
        .await
        .expect("ensure_entity ai_model");
    for logicalname in ["name", "provider_model_id"] {
        ensure_attribute(
            db,
            model,
            logicalname,
            logicalname,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_model.{logicalname}: {e:?}"));
    }

    // D-566 — the AI Provider catalog, for the credential-rotation route.
    // Only the columns `attome_ai::provider::load` selects and the handler
    // writes; the full bundle is not needed to drive this route.
    let provider = ensure_entity(db, "ai_provider", "AI Provider", Some("name"), false)
        .await
        .expect("ensure_entity ai_provider");
    for logicalname in [
        "name",
        "provider_id",
        "endpoint_url",
        "api_protocol",
        "credential_ref",
    ] {
        ensure_attribute(
            db,
            provider,
            logicalname,
            logicalname,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_provider.{logicalname}: {e:?}"));
    }
    // D-568 — `provider::load` also selects this per-provider switch.
    ensure_attribute(
        db,
        provider,
        "allow_external_endpoint",
        "allow_external_endpoint",
        "bool",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("ensure_attribute ai_provider.allow_external_endpoint: {e:?}"));

    let agent = ensure_entity(db, "ai_agent", "AI Agent", Some("name"), false)
        .await
        .expect("ensure_entity ai_agent");
    for logicalname in [
        "name",
        "status",
        "primary_model_ref",
        "system_instructions",
        "policy_ref",
    ] {
        ensure_attribute(
            db,
            agent,
            logicalname,
            logicalname,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_agent.{logicalname}: {e:?}"));
    }

    let policy = ensure_entity(
        db,
        "ai_agent_policy",
        "AI Agent Policy",
        Some("name"),
        false,
    )
    .await
    .expect("ensure_entity ai_agent_policy");
    let action_choices = json!({
        "choices": attome_ai::ActionRegistry::new()
            .all()
            .map(|descriptor| descriptor.id.as_str())
            .collect::<Vec<_>>(),
        "multi": true,
    });
    for (logicalname, field_type, options) in [
        ("name", "text", None),
        ("risk_ceiling", "text", None),
        ("allowed_action_ids", "choice", Some(action_choices)),
        ("knowledge_source_refs", "text", None),
        ("max_invocations_per_session", "number", None),
        ("max_writes_per_day", "number", None),
        ("max_tokens_per_session", "number", None),
        ("max_session_duration_minutes", "number", None),
    ] {
        ensure_attribute(
            db,
            policy,
            logicalname,
            logicalname,
            field_type,
            false,
            false,
            false,
            false,
            None,
            options,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_agent_policy.{logicalname}: {e:?}"));
    }
}

async fn seed_user(state: &AppState, label: &str) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("audit-emit-{label}-{user_id}@example.test");
    let password_hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash throwaway password");
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("audit-emit-{label}-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

/// A session token naming a real refresh family. With `stepped_up`, the
/// family holds a fresh password step-up (the values a verified step-up
/// writes; the step-up itself is `step_up_http.rs`'s subject).
async fn session_token(state: &AppState, user_id: Uuid, stepped_up: bool) -> String {
    let issued = attome_auth::refresh::issue(
        &state.db,
        user_id,
        &attome_auth::auth_context::AuthContext::password(),
        attome_auth::refresh::RefreshLifetimes {
            idle_secs: state.config.refresh_token_expiry_secs(),
            absolute_secs: state.config.refresh_absolute_lifetime_secs(),
        },
        &state.pepper_ring(),
    )
    .await
    .expect("issue a refresh family");
    if stepped_up {
        sqlx::query(
            "UPDATE refresh_token
             SET auth_time = NOW(), amr = ARRAY['pwd'], elevated_until = NOW() + INTERVAL '15 minutes'
             WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(issued.family_id)
        .execute(&state.db)
        .await
        .expect("record a password step-up on the family");
    }
    attome_auth::accounts::issue_access_token(
        &state.db,
        user_id,
        issued.family_id,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        3600,
    )
    .await
    .expect("issue a session token naming the family")
}

fn request(method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ORIGIN);
    if let Some(token) = token {
        builder = builder.header(header::COOKIE, format!("__Host-session_token={token}"));
    }
    let mut req = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("build request");
    // The login routes key their throttle and failed-login coalescing on the
    // peer address.
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 40_009))));
    req
}

/// Logs `email` in with the shared password and returns its `name=value`
/// cookie pairs (session and refresh).
async fn login_cookies(fx: &Fx, email: &str) -> Vec<String> {
    let res = fx
        .app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"email": email, "password": PASSWORD})),
        ))
        .await
        .expect("login");
    assert!(
        res.status().is_success(),
        "fixture login failed: {}",
        res.status()
    );
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next().map(str::to_owned))
        .filter(|pair| !pair.ends_with('='))
        .collect()
}

fn with_cookies(mut req: Request<Body>, cookies: &[String]) -> Request<Body> {
    req.headers_mut().insert(
        header::COOKIE,
        cookies.join("; ").parse().expect("cookie header"),
    );
    req
}

/// A pending-MFA token of `typ` for `user_id`, minted the way login mints one.
async fn pending_token(fx: &Fx, user_id: Uuid, typ: attome_auth::TokenType) -> String {
    attome_auth::mfa::start_challenge(
        &fx.base.redis_coordination,
        user_id,
        typ,
        &fx.base.secrets.load().jwt_secret,
        &fx.base.config.auth.jwt_issuer,
        fx.base.config.jwt_audience(),
    )
    .await
    .expect("mint a pending MFA token")
}

/// Sends a fixture request and returns its JSON body, panicking on a non-2xx.
async fn call(fx: &Fx, req: Request<Body>) -> Value {
    let label = format!("{} {}", req.method(), req.uri());
    let res = fx.app.clone().oneshot(req).await.expect("send");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert!(
        status.is_success(),
        "fixture call {label} failed: {status} {body}"
    );
    body
}

async fn admin(fx: &Fx, method: &str, uri: &str, body: Option<Value>) -> Value {
    call(fx, request(method, uri, Some(&fx.admin_token), body)).await
}

fn id_of(v: &Value) -> Uuid {
    v["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("response has no id: {v}"))
}

fn uniq(label: &str) -> String {
    format!("audit-emit-{label}-{}", Uuid::now_v7().simple())
}

/// Returns `(entity_id, record_id)`.
async fn provision_entity_and_record(fx: &Fx) -> (Uuid, Uuid) {
    let entity = admin(
        fx,
        "POST",
        "/api/v1/admin/entities",
        Some(json!({"logicalname": fx.entity, "name": "Audit Emission"})),
    )
    .await;
    let entity_id = id_of(&entity);
    admin(
        fx,
        "POST",
        &format!("/api/v1/admin/entities/{entity_id}/fields"),
        Some(json!({"logicalname": "title", "name": "Title", "field_type": "text", "is_filterable": true})),
    )
    .await;
    let registry = attome_core::build_registry(&fx.base.db)
        .await
        .expect("build metadata registry");
    fx.xrm.entities.swap(registry);
    let record = admin(
        fx,
        "POST",
        &format!("/api/v1/{}", fx.entity),
        Some(json!({"title": "audit emission record"})),
    )
    .await;
    (entity_id, id_of(&record))
}

/// A fresh record on the throwaway entity with `title`.
async fn entity_record(fx: &Fx, title: &str) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            &format!("/api/v1/{}", fx.entity),
            Some(json!({"title": title})),
        )
        .await,
    )
}

/// A recovery-archive row (D-788 rule 9) holding a `title` value for a fresh
/// record whose `title` is empty, so a restore fills it; returns the row id.
/// Sealed through `recovery_archive::insert_batch` under the test ring, the
/// same write a field delete makes.
async fn archived_value(fx: &Fx) -> Uuid {
    let record_id = entity_record(fx, "to be emptied").await;
    sqlx::query(&format!(
        "UPDATE {} SET title = NULL WHERE id = $1",
        attome_core::quote_ident(&fx.entity)
    ))
    .bind(record_id)
    .execute(&fx.base.db)
    .await
    .expect("empty the record's title");
    let attribute_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM attribute_info WHERE entity_ref = $1 AND logicalname = 'title'",
    )
    .bind(fx.entity_id)
    .fetch_one(&fx.base.db)
    .await
    .expect("title attribute");
    let ring = attome_core::recovery_archive::ring(fx.base.config.as_ref())
        .expect("test config carries the recovery-archive ring");
    let event = attome_core::recovery_archive::ArchiveEvent {
        reason: attome_core::recovery_archive::ArchiveReason::FieldDeleted,
        entity: &fx.entity,
        field: "title",
        attribute_id,
        field_type: "text",
        sensitive: false,
        op: None,
        run_ref: None,
        retention_days: None,
    };
    let mut conn = fx.base.db.acquire().await.expect("connection");
    attome_core::recovery_archive::insert_batch(
        &mut conn,
        ring,
        &event,
        &[(record_id, json!("restored title"))],
    )
    .await
    .expect("archive a value");
    sqlx::query_scalar("SELECT id FROM recovery_archive WHERE record_id = $1")
        .bind(record_id)
        .fetch_one(&fx.base.db)
        .await
        .expect("archive row")
}

/// A release-report item (D-788 Topic 14) of `kind` on the fixture entity's
/// `title`, in a standalone report (no apply in progress); returns its id.
/// A conflict's values are sealed under the test ring, as an apply seals
/// them.
async fn report_item(
    fx: &Fx,
    kind: attome_core::release_report::ItemKind,
    record_id: Option<Uuid>,
    values: Option<attome_core::release_report::ConflictValues>,
) -> Uuid {
    use attome_core::release_report as rr;
    let ring = attome_core::recovery_archive::ring(fx.base.config.as_ref());
    let mut tx = attome_db::tx::begin(&fx.base.db).await.expect("begin");
    let report = rr::insert_items(
        &mut tx,
        ring,
        vec![rr::NewItem {
            kind,
            entity: fx.entity.clone(),
            field: Some("title".to_owned()),
            record_id,
            object_kind: None,
            object_ref: None,
            detail: json!({ "emission": true }),
            values,
            op: None,
        }],
        "audit emission",
    )
    .await
    .expect("insert the item")
    .expect("a report");
    attome_db::tx::commit(tx).await.expect("commit");
    sqlx::query_scalar("SELECT id FROM release_report_item WHERE report_ref = $1")
        .bind(report)
        .fetch_one(&fx.base.db)
        .await
        .expect("item id")
}

/// An open record conflict on a fresh record's `title` (customer value
/// kept); returns `(item id, the record's row_version)`.
async fn conflict_item(fx: &Fx) -> (Uuid, i64) {
    let record_id = entity_record(fx, "customer title").await;
    let item = report_item(
        fx,
        attome_core::release_report::ItemKind::Conflict,
        Some(record_id),
        Some(attome_core::release_report::ConflictValues {
            theirs: json!("customer title"),
            ours: json!("our title"),
            key: None,
        }),
    )
    .await;
    let row_version: i64 = sqlx::query_scalar(&format!(
        "SELECT row_version FROM {} WHERE id = $1",
        attome_core::quote_ident(&fx.entity)
    ))
    .bind(record_id)
    .fetch_one(&fx.base.db)
    .await
    .expect("record row_version");
    (item, row_version)
}

/// A published stored query (no entity, no required privilege: admin-only).
async fn stored_query(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/queries",
            Some(json!({"sql_query": "SELECT 1 AS id"})),
        )
        .await,
    )
}

fn view_body(fx: &Fx, query_id: Uuid) -> Value {
    json!({
        "name": uniq("view"),
        "entity_logical_name": fx.entity_id,
        "sql_query_ref": query_id,
        "table_definition": [],
    })
}

async fn system_view(fx: &Fx) -> Uuid {
    let query_id = stored_query(fx).await;
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/views",
            Some(view_body(fx, query_id)),
        )
        .await,
    )
}

/// A sidebar item; returns `(id, row_version)`.
async fn sidebar_item(fx: &Fx) -> (Uuid, i64) {
    let item = admin(
        fx,
        "POST",
        "/api/v1/sidebar/admin",
        Some(json!({"name": uniq("sidebar"), "display_order": 900})),
    )
    .await;
    let row_version = item["row_version"]
        .as_i64()
        .unwrap_or_else(|| panic!("sidebar item has no row_version: {item}"));
    (id_of(&item), row_version)
}

/// An inactive approval policy for an action type nothing else submits, so it
/// can never gate another driver's route.
async fn approval_policy(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/approval-policies",
            Some(approval_policy_body(fx)),
        )
        .await,
    )
}

fn approval_policy_body(fx: &Fx) -> Value {
    json!({
        "name": uniq("policy"),
        "is_active": false,
        "action_type": format!("audit_emit.{}", Uuid::now_v7().simple()),
        "plan": {"steps": [{
            "mode": "any",
            "approvers": [format!("user:{}", fx.admin_id)],
            "sla_minutes": 60,
            "on_timeout": "escalate",
        }]},
    })
}

/// An active agent definition with a live model and an open agent policy.
async fn agent_definition(fx: &Fx) -> Uuid {
    let db = &fx.base.db;
    let model = Uuid::now_v7();
    sqlx::query("INSERT INTO ai_model (id, name, created_at) VALUES ($1, 'emission model', NOW())")
        .bind(model)
        .execute(db)
        .await
        .expect("insert ai_model row");
    let policy = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent_policy \
            (id, name, risk_ceiling, max_invocations_per_session, max_writes_per_day, \
             max_tokens_per_session, max_session_duration_minutes, created_at) \
         VALUES ($1, 'emission policy', 'consequential', 1000, 1000, 200000, 600, NOW())",
    )
    .bind(policy)
    .execute(db)
    .await
    .expect("insert ai_agent_policy row");
    let definition = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent \
            (id, name, status, primary_model_ref, system_instructions, policy_ref, created_at) \
         VALUES ($1, 'emission agent', 'active', $2, 'Be concise.', $3, NOW())",
    )
    .bind(definition)
    .bind(model)
    .bind(policy)
    .execute(db)
    .await
    .expect("insert ai_agent row");
    definition
}

/// The commands that make a startable agent object (V2-D487): a model, a
/// policy, no tools and a handoff contract.
fn agent_commands(model: Uuid, policy: Uuid) -> Value {
    json!([
        {"op": "set", "path": "/role", "value": "Emission tester"},
        {"op": "set", "path": "/instructions", "value": "Answer briefly."},
        {"op": "set", "path": "/tools", "value": []},
        {"op": "set", "path": "/limits", "value": {"max_steps": 5, "max_tool_calls": 5, "max_tokens": 2000}},
        {"op": "set", "path": "/persona", "value": {"model": model.to_string()}},
        {"op": "set", "path": "/policy", "value": policy.to_string()},
        {"op": "set", "path": "/handoff", "value": {"input": {"type": "object"}, "output": {"type": "object"}}},
    ])
}

/// A published agent object with a live model and an open agent policy,
/// built through the admin model API.
async fn agent_object(fx: &Fx) -> Uuid {
    let db = &fx.base.db;
    let model = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_model (id, name, created_at) VALUES ($1, 'emission object model', NOW())",
    )
    .bind(model)
    .execute(db)
    .await
    .expect("insert ai_model row");
    let policy = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent_policy \
            (id, name, risk_ceiling, max_invocations_per_session, max_writes_per_day, \
             max_tokens_per_session, max_session_duration_minutes, created_at) \
         VALUES ($1, 'emission object policy', 'consequential', 1000, 1000, 200000, 600, NOW())",
    )
    .bind(policy)
    .execute(db)
    .await
    .expect("insert ai_agent_policy row");
    let id = Uuid::now_v7();
    let t = Some(fx.admin_token.as_str());
    call(
        fx,
        request(
            "POST",
            &format!("/api/v1/admin/model/agent/{id}/commands"),
            t,
            Some(json!({
                "base_hash": "",
                "name": format!("emission agent {id}"),
                "commands": agent_commands(model, policy),
            })),
        ),
    )
    .await;
    call(
        fx,
        request(
            "POST",
            &format!("/api/v1/admin/model/agent/{id}/publish"),
            t,
            None,
        ),
    )
    .await;
    id
}

/// An eval suite draft (N23) for a published agent object, with one case.
async fn eval_suite(fx: &Fx) -> Uuid {
    let agent = agent_object(fx).await;
    let id = Uuid::now_v7();
    call(
        fx,
        request(
            "POST",
            &format!("/api/v1/admin/model/eval_suite/{id}/commands"),
            Some(fx.admin_token.as_str()),
            Some(json!({
                "base_hash": "",
                "name": format!("emission suite {id}"),
                "commands": [
                    {"op": "set", "path": "/agent", "value": agent.to_string()},
                    {"op": "set", "path": "/pass_threshold", "value": 1.0},
                    {"op": "set", "path": "/cases", "value": [{"name": "greets", "input": "Hello", "expect": {}}]},
                ],
            })),
        ),
    )
    .await;
    id
}

/// An assistant message answering a person's question, in a chat
/// conversation (N23-T3's source for an eval case).
async fn answered_message(fx: &Fx) -> Uuid {
    let conversation = chat_conversation(fx).await;
    let turn_id = Uuid::now_v7();
    let mut last = Uuid::nil();
    for (role, content) in [
        (attome_ai::conversation::Role::User, "What is my balance?"),
        (
            attome_ai::conversation::Role::Assistant,
            "Your balance is 10.",
        ),
    ] {
        last = attome_ai::conversation::append(
            &fx.base.db,
            attome_ai::conversation::NewMessage {
                conversation_id: conversation,
                role,
                content: content.to_owned(),
                turn_id,
                terminal_state: None,
                model_id: None,
                prompt_version: None,
                input_tokens: None,
                output_tokens: None,
            },
        )
        .await
        .expect("append a message")
        .id;
    }
    last
}

/// C4 — a conversation owned by the fixture's admin, on a fresh
/// `Reversible` agent session. Seeded through the engine rather than the
/// start route, so the chat drivers below do not depend on that route.
async fn chat_conversation(fx: &Fx) -> Uuid {
    let session = attome_ai::session::start(
        &fx.base.db,
        &attome_audit::audit_service(&fx.xrm),
        attome_ai::session::SessionStart {
            owner_user_id: fx.admin_id,
            risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start an agent session");
    attome_ai::conversation::create(
        &fx.base.db,
        attome_ai::conversation::NewConversation {
            agent_session_id: session.id,
            owner_user_id: fx.admin_id,
            agent_definition_ref: None,
            surface: attome_ai::conversation::Surface::Internal,
            title: None,
        },
    )
    .await
    .expect("create a conversation")
    .id
}

/// C4 — a server-persisted `record.update_field` proposal on the fixture's
/// entity (`title`, allow-listed here), as a turn would have left it.
/// Returns `(conversation, tool_call_id, arguments_hash)`.
async fn chat_proposal(fx: &Fx) -> (Uuid, String, String) {
    let conversation = chat_conversation(fx).await;
    sqlx::query(
        "DELETE FROM setting WHERE key = 'ai.record_update_field_allowlist' \
            AND scope = 'deployment' AND scope_ref IS NULL",
    )
    .execute(&fx.base.db)
    .await
    .expect("clear the allow-list");
    sqlx::query(
        "INSERT INTO setting (key, scope, scope_ref, value, schema) \
         VALUES ('ai.record_update_field_allowlist', 'deployment', NULL, $1, $2)",
    )
    .bind(json!({ fx.entity.clone(): ["title"] }))
    .bind(json!({"type": "object"}))
    .execute(&fx.base.db)
    .await
    .expect("allow-list the fixture entity's title");
    fx.xrm.settings.swap(
        attome_core::load_all_settings(&fx.base.db)
            .await
            .expect("reload settings"),
    );
    let table = attome_core::quote_ident(&fx.entity);
    let row_version: i64 =
        sqlx::query_scalar(&format!("SELECT row_version FROM {table} WHERE id = $1"))
            .bind(fx.record_id)
            .fetch_one(&fx.base.db)
            .await
            .expect("read the record's row_version");
    let tool_call_id = format!("emission-{}", Uuid::now_v7().simple());
    let hash = attome_ai::tool_call::propose(
        &fx.base.db,
        attome_ai::tool_call::NewToolCall {
            conversation_id: conversation,
            message_id: None,
            turn_id: Uuid::now_v7(),
            tool_call_id: Some(tool_call_id.clone()),
            action_id: "record.update_field".into(),
            arguments: json!({
                "entity": fx.entity, "record_id": fx.record_id, "field": "title",
                "value": uniq("confirmed"), "row_version": row_version,
            }),
            initiator_is_agent: true,
            gate_decision: None,
        },
    )
    .await
    .expect("persist a proposal")
    .arguments_hash;
    (conversation, tool_call_id, hash)
}

/// An enabled `authenticated` portal and a provisioned (invited) user on it,
/// through the engine functions. Returns the portal and the user's id/email.
async fn portal_with_invited_user(
    fx: &Fx,
) -> (attome_portal::provision::PortalDetail, Uuid, String) {
    let mut tx = fx.base.db.begin().await.expect("begin");
    let portal = attome_portal::provision::create_portal(
        &mut tx,
        fx.admin_id,
        attome_portal::provision::NewPortal {
            name: "audit emission portal".into(),
            description: None,
            keyword: portal_keyword(),
            portal_type: attome_portal::provision::PortalType::Authenticated,
            is_enabled: true,
            owning_team_ref: None,
            mfa_policy: Default::default(),
        },
    )
    .await
    .expect("create portal");
    let email = format!("{}@example.com", uniq("portal-user"));
    let user = attome_portal::provision::create_user(
        &mut tx,
        fx.admin_id,
        portal.id,
        attome_portal::provision::NewPortalUser {
            name: "Ada".into(),
            email: Some(email.clone()),
            username: None,
        },
    )
    .await
    .expect("create portal user");
    tx.commit().await.expect("commit");
    (portal, user.id, email)
}

/// As [`portal_with_invited_user`], with the invitation already accepted
/// (password [`PASSWORD`]), so the user can log in.
async fn portal_with_active_user(
    fx: &Fx,
) -> (attome_portal::provision::PortalDetail, Uuid, String) {
    let (portal, user, email) = portal_with_invited_user(fx).await;
    let mut tx = fx.base.db.begin().await.expect("begin");
    let (_, invitation) =
        attome_portal::auth::issue_invitation(&mut tx, &fx.base.pepper_ring(), portal.id, user)
            .await
            .expect("issue invitation")
            .expect("invited user");
    let hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash");
    attome_portal::auth::accept_invitation(
        &mut tx,
        &fx.base.pepper_ring(),
        &portal,
        &invitation.bearer,
        &hash,
    )
    .await
    .expect("accept invitation")
    .expect("a live invitation");
    tx.commit().await.expect("commit");
    (portal, user, email)
}

/// A portal role on a fresh portal. Returns `(portal_id, role_id)`.
async fn portal_role(fx: &Fx) -> (Uuid, Uuid) {
    let (portal, _, _) = portal_with_invited_user(fx).await;
    let role = admin(
        fx,
        "POST",
        &format!("/api/v1/admin/webportals/{}/roles", portal.id),
        Some(json!({"name": uniq("role")})),
    )
    .await;
    (portal.id, id_of(&role))
}

/// A valid conditioned grant on the harness's throwaway entity (`title` is
/// filterable, so it can scope a portal grant).
fn portal_grant_body() -> Value {
    json!({
        "can_read": true,
        "conditions": [{"field": "title", "operator": "eq", "value": "audit emission"}],
        "fields": [{"field": "title", "can_read": true}],
    })
}

/// Logs a portal user in over HTTP and returns the cookie pairs it set.
async fn portal_login(fx: &Fx, keyword: &str, email: &str) -> Vec<String> {
    let res = fx
        .app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/{keyword}/api/v1/auth/login"),
            None,
            Some(json!({"email": email, "password": PASSWORD})),
        ))
        .await
        .expect("portal login");
    assert!(res.status().is_success(), "portal login: {}", res.status());
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next().map(str::to_owned))
        .filter(|pair| !pair.ends_with('='))
        .collect()
}

/// Enrolls and confirms MFA for a logged-in portal session; returns the
/// secret and the time the confirming code was generated for.
async fn portal_enroll_mfa(fx: &Fx, keyword: &str, cookies: &[String]) -> (String, u64) {
    let enrolled = call(
        fx,
        with_cookies(
            request(
                "POST",
                &format!("/{keyword}/api/v1/auth/mfa/enroll"),
                None,
                None,
            ),
            cookies,
        ),
    )
    .await;
    let secret = enrolled["secret"].as_str().expect("secret").to_owned();
    let now = u64::try_from(chrono::Utc::now().timestamp()).expect("time");
    let res = fx
        .app
        .clone()
        .oneshot(with_cookies(
            request(
                "POST",
                &format!("/{keyword}/api/v1/auth/mfa/confirm"),
                None,
                Some(json!({"code": attome_portal::mfa::code_at(&secret, now).expect("code")})),
            ),
            cookies,
        ))
        .await
        .expect("confirm");
    assert_eq!(res.status(), StatusCode::OK, "mfa confirm");
    (secret, now)
}

/// A portal keyword: `[a-z0-9-]`, 3 to 40 characters (`attome_portal::keyword`),
/// which [`uniq`]'s 40-plus-character labels would exceed.
fn portal_keyword() -> String {
    format!("ae-{}", &Uuid::now_v7().simple().to_string()[20..])
}

/// A fresh `authenticated` web portal, through its own admin route. Returns the
/// response body (`id`, `row_version`, …).
async fn webportal(fx: &Fx) -> Value {
    admin(
        fx,
        "POST",
        "/api/v1/admin/webportals",
        Some(json!({
            "name": "audit emission portal",
            "keyword": portal_keyword(),
            "portal_type": "authenticated",
        })),
    )
    .await
}

/// Returns `(portal_id, user_id)` for a freshly provisioned portal user.
async fn webportal_user(fx: &Fx) -> (Uuid, Uuid) {
    let portal = id_of(&webportal(fx).await);
    let user = admin(
        fx,
        "POST",
        &format!("/api/v1/admin/webportals/{portal}/users"),
        Some(json!({"name": "Ada", "email": format!("{}@example.com", uniq("portal"))})),
    )
    .await;
    (portal, id_of(&user))
}

async fn role(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/security/roles",
            Some(json!({"name": uniq("role")})),
        )
        .await,
    )
}

/// One `ai_provider` row for the credential-rotation driver. Seeded on the
/// raw pool (this file's module-level `disallowed_methods` allowance) rather
/// than through generic CRUD, so the driver does not depend on that route's own
/// audit behaviour.
/// A query-backed metric over a published stored query (D-786): its first
/// compute provisions the metric service principal's role membership, the
/// Access/Grant half of `POST /api/v1/metrics/{id}/compute`'s x-audit.
async fn query_metric(fx: &Fx) -> Uuid {
    let db = &fx.base.db;
    let query_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, is_active, is_report, owner_layer) VALUES ($1, 'SELECT 7::float8 AS value', true, true, 'project')",
    )
    .bind(query_id)
    .execute(db)
    .await
    .expect("insert stored query");
    sqlx::query(
        "INSERT INTO sql_query_version (id, query_id, sql_query, cost_estimate) VALUES ($1, $2, 'SELECT 7::float8 AS value', 0)",
    )
    .bind(Uuid::now_v7())
    .bind(query_id)
    .execute(db)
    .await
    .expect("insert published query version");
    let metric_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition (id, name, key, source_kind, query_ref, direction, period) VALUES ($1, $2, $3, 'query', $4, 'higher_is_better', 'month')",
    )
    .bind(metric_id)
    .bind(format!("Emission Metric {metric_id}"))
    .bind(format!("emission_metric_{}", metric_id.simple()))
    .bind(query_id.to_string())
    .execute(db)
    .await
    .expect("insert query metric definition");
    metric_id
}

async fn ai_provider(fx: &Fx) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO ai_provider (name, provider_id, endpoint_url, api_protocol) \
         VALUES ($1, $2, 'http://127.0.0.1:8000/v1', 'openai-completions') RETURNING id",
    )
    .bind(uniq("provider"))
    .bind(uniq("pid"))
    .fetch_one(&fx.base.db)
    .await
    .expect("seed ai_provider")
}

async fn team(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/security/teams",
            Some(json!({"name": uniq("team")})),
        )
        .await,
    )
}

async fn position(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/security/positions",
            Some(json!({"name": uniq("position")})),
        )
        .await,
    )
}

async fn field_profile(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/security/field-profiles",
            Some(json!({"name": uniq("profile")})),
        )
        .await,
    )
}

async fn organization(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO organization (id, is_active, name) VALUES ($1, true, $2)")
        .bind(id)
        .bind(uniq("org"))
        .execute(&fx.base.db)
        .await
        .expect("insert organization");
    id
}

async fn role_grant(fx: &Fx, role_id: Uuid, privilege_key: &str) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/security/role-grants",
            Some(json!({"role_id": role_id, "privilege_key": privilege_key})),
        )
        .await,
    )
}

async fn s2s_client(fx: &Fx) -> Uuid {
    let (service_user, _) = seed_user(&fx.base, "s2s-service").await;
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/s2s/clients",
            Some(json!({
                "client_id": uniq("client"),
                "name": "audit emission client",
                "service_user_ref": service_user,
            })),
        )
        .await,
    )
}

fn totp_for(secret_base32: &str) -> Totp {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(secret_base32).expect("base32 secret"))
        .with_account_name("test".to_string())
        .build()
        .expect("build totp")
}

fn code_at_offset(totp: &Totp, offset_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    totp.generate(now + offset_secs).to_string()
}

/// A user with a confirmed TOTP enrollment; returns the TOTP generator.
async fn enrolled_user(fx: &Fx, label: &str) -> (Uuid, Totp) {
    let (user_id, totp, _) = enrolled_user_with_codes(fx, label).await;
    (user_id, totp)
}

async fn enrolled_user_with_codes(fx: &Fx, label: &str) -> (Uuid, Totp, Vec<String>) {
    let (user_id, _) = seed_user(&fx.base, label).await;
    let ring = fx.base.secrets.load().mfa_encryption_key.clone();
    let enrolled = attome_auth::mfa::enroll(&fx.base.db, &ring, user_id)
        .await
        .expect("enroll");
    let totp = totp_for(&enrolled.secret_base32);
    let codes = attome_auth::mfa::confirm_enrollment(
        &fx.base.db,
        &ring,
        &fx.base.pepper_ring(),
        user_id,
        &totp.generate_current().to_string(),
    )
    .await
    .expect("confirm enrollment");
    (user_id, totp, codes)
}

/// Builds the request that exercises `key`, after creating whatever it needs,
/// with the status it must answer (`None`: any 2xx). `None` overall means no
/// driver exists — a test failure for a mapped route.
async fn drive(fx: &Fx, key: &str) -> Option<(Request<Body>, Option<StatusCode>)> {
    let t = Some(fx.admin_token.as_str());
    const S: &str = "/api/v1/admin/security";
    let req = match key {
        // ── attome-profiler ───────────────────────────────────────────────────
        // D-542 mandatory policy: the audited reset is a Configuration
        // HardDelete, so the emission test must drive it.
        "DELETE /api/v1/admin/profiler/stats" => {
            request("DELETE", "/api/v1/admin/profiler/stats", t, None)
        }

        // ── environment variables (A30-T1) ──────────────────────────────────
        "DELETE /api/v1/admin/env-variables/{name}" => {
            sqlx::query(
                "INSERT INTO environment_variable_value (name, value, updated_by) VALUES ('emission_env', '\"x\"'::jsonb, $1) ON CONFLICT (name) DO NOTHING",
            )
            .bind(Uuid::nil())
            .execute(&fx.base.db)
            .await
            .expect("seed an environment variable value");
            request(
                "DELETE",
                "/api/v1/admin/env-variables/emission_env",
                t,
                None,
            )
        }

        // ── customer tests (Z15-T13) ────────────────────────────────────────
        "POST /api/v1/admin/customer-tests" => request(
            "POST",
            "/api/v1/admin/customer-tests",
            t,
            Some(json!({"name": format!("emission-{}", Uuid::now_v7()), "definition": {}})),
        ),
        "PATCH /api/v1/admin/customer-tests/{id}" => {
            let id = customer_test(fx).await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/customer-tests/{id}"),
                    t,
                    Some(json!({"description": "changed"})),
                ),
                1,
            )
        }
        "DELETE /api/v1/admin/customer-tests/{id}" => {
            let id = customer_test(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/customer-tests/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/customer-tests/{id}/run" => {
            let id = customer_test(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/customer-tests/{id}/run"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/customer-tests/run-all" => {
            customer_test(fx).await;
            request("POST", "/api/v1/admin/customer-tests/run-all", t, None)
        }
        "POST /api/v1/admin/customer-tests/import" => request(
            "POST",
            "/api/v1/admin/customer-tests/import",
            t,
            Some(json!({
                "format": "attome-customer-tests/v1",
                "tests": [{"name": format!("emission-import-{}", Uuid::now_v7()), "definition": {}}]
            })),
        ),

        // ── SLO targets (AA13-T8) ───────────────────────────────────────────
        "PUT /api/v1/admin/slo/targets/{class_id}" => {
            sqlx::query("DELETE FROM ops_slo_target_override WHERE class_id = 'S1'")
                .execute(&fx.base.db)
                .await
                .expect("clear S1 override");
            request(
                "PUT",
                "/api/v1/admin/slo/targets/S1",
                t,
                Some(json!({"p95_ms": 40, "p99_ms": 90})),
            )
        }
        "DELETE /api/v1/admin/slo/targets/{class_id}" => {
            sqlx::query(
                "INSERT INTO ops_slo_target_override (class_id, p95_ms, p99_ms, updated_by) VALUES ('S2', 400, 700, $1) ON CONFLICT (class_id) DO NOTHING",
            )
            .bind(Uuid::nil())
            .execute(&fx.base.db)
            .await
            .expect("seed S2 override");
            request("DELETE", "/api/v1/admin/slo/targets/S2", t, None)
        }

        // ── follow-up rules (AI4-T6) ────────────────────────────────────────
        "POST /api/v1/admin/ai/follow-up-rules/{id}/run" => {
            // The rule entity comes from a platform changeset this fixture does
            // not apply; provision it here (a throwaway database).
            let entity = attome_metadata::provision::ensure_entity(
                &fx.base.db,
                "ai_followup_rule",
                "Follow-up Rule",
                None,
                false,
            )
            .await
            .expect("follow-up rule entity");
            for (name, kind) in [
                ("name", "text"),
                ("reason", "text"),
                ("target_entity", "text"),
                ("idle_days", "number"),
            ] {
                attome_metadata::provision::ensure_attribute(
                    &fx.base.db,
                    entity,
                    name,
                    name,
                    kind,
                    false,
                    false,
                    false,
                    false,
                    None,
                    None,
                )
                .await
                .expect("follow-up rule attribute");
            }
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO ai_followup_rule (id, name, reason, target_entity, idle_days, is_active) \
                 VALUES ($1, 'Emission rule', 'overdue_task', 'activity', 3, true)",
            )
            .bind(id)
            .execute(&fx.base.db)
            .await
            .expect("insert follow-up rule");
            request(
                "POST",
                &format!("/api/v1/admin/ai/follow-up-rules/{id}/run"),
                t,
                None,
            )
        }

        // ── metrics (D-786) ─────────────────────────────────────────────────
        "POST /api/v1/metrics/{id}/compute" => {
            let id = query_metric(fx).await;
            request(
                "POST",
                &format!("/api/v1/metrics/{id}/compute"),
                t,
                Some(json!({})),
            )
        }

        // ── AI providers (D-566) ────────────────────────────────────────────
        "POST /api/v1/admin/ai/providers/{id}/credential" => {
            let id = ai_provider(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/ai/providers/{id}/credential"),
                t,
                Some(json!({"api_key": "sk-test-emission-0000"})),
            )
        }

        // ── roles and grants ────────────────────────────────────────────────
        "POST /api/v1/admin/security/roles" => request(
            "POST",
            &format!("{S}/roles"),
            t,
            Some(json!({"name": uniq("role")})),
        ),
        "PATCH /api/v1/admin/security/roles/{id}" => {
            let id = role(fx).await;
            request(
                "PATCH",
                &format!("{S}/roles/{id}"),
                t,
                Some(json!({"name": uniq("renamed")})),
            )
        }
        "PUT /api/v1/admin/security/roles/{id}/position-hierarchy" => {
            let id = role(fx).await;
            request(
                "PUT",
                &format!("{S}/roles/{id}/position-hierarchy"),
                t,
                Some(json!({"position_hierarchy_enabled": true})),
            )
        }
        "POST /api/v1/admin/security/role-grants" => {
            let id = role(fx).await;
            request(
                "POST",
                &format!("{S}/role-grants"),
                t,
                Some(json!({"role_id": id, "privilege_key": "audit_emit.read"})),
            )
        }
        "DELETE /api/v1/admin/security/role-grants/{id}" => {
            let grant = role_grant(fx, role(fx).await, "audit_emit.write").await;
            request("DELETE", &format!("{S}/role-grants/{grant}"), t, None)
        }
        "POST /api/v1/admin/security/role-grants/{grant_id}/conditions" => {
            let grant = role_grant(fx, role(fx).await, &format!("{}.read", fx.entity)).await;
            request(
                "POST",
                &format!("{S}/role-grants/{grant}/conditions"),
                t,
                Some(json!({"field_logicalname": "title", "operator": 0, "value": "x"})),
            )
        }
        "DELETE /api/v1/admin/security/role-grants/{grant_id}/conditions/{condition_id}" => {
            let grant = role_grant(fx, role(fx).await, &format!("{}.read", fx.entity)).await;
            let condition = admin(
                fx,
                "POST",
                &format!("{S}/role-grants/{grant}/conditions"),
                Some(json!({"field_logicalname": "title", "operator": 0, "value": "y"})),
            )
            .await;
            let cid = id_of(&condition);
            request(
                "DELETE",
                &format!("{S}/role-grants/{grant}/conditions/{cid}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/security/role-entity-access" => {
            let id = role(fx).await;
            request(
                "POST",
                &format!("{S}/role-entity-access"),
                t,
                Some(json!({"role_id": id, "entity": fx.entity})),
            )
        }
        "DELETE /api/v1/admin/security/role-entity-access/{id}" => {
            let rid = role(fx).await;
            let row = admin(
                fx,
                "POST",
                &format!("{S}/role-entity-access"),
                Some(json!({"role_id": rid, "entity": fx.entity})),
            )
            .await;
            request(
                "DELETE",
                &format!("{S}/role-entity-access/{}", id_of(&row)),
                t,
                None,
            )
        }
        "POST /api/v1/admin/security/users/{id}/roles" => {
            let (user, _) = seed_user(&fx.base, "role-holder").await;
            let rid = role(fx).await;
            request(
                "POST",
                &format!("{S}/users/{user}/roles"),
                t,
                Some(json!({"role_id": rid})),
            )
        }
        "DELETE /api/v1/admin/security/users/{id}/roles/{role_id}" => {
            let (user, _) = seed_user(&fx.base, "role-holder").await;
            let rid = role(fx).await;
            admin(
                fx,
                "POST",
                &format!("{S}/users/{user}/roles"),
                Some(json!({"role_id": rid})),
            )
            .await;
            request("DELETE", &format!("{S}/users/{user}/roles/{rid}"), t, None)
        }
        "POST /api/v1/admin/security/grants" => {
            let (_, email) = seed_user(&fx.base, "grantee").await;
            request(
                "POST",
                &format!("{S}/grants"),
                t,
                Some(json!({"user_email": email, "privilege_key": "audit_emit.direct"})),
            )
        }
        "DELETE /api/v1/admin/security/grants/{id}" => {
            let (_, email) = seed_user(&fx.base, "grantee").await;
            let grant = admin(
                fx,
                "POST",
                &format!("{S}/grants"),
                Some(json!({"user_email": email, "privilege_key": "audit_emit.direct"})),
            )
            .await;
            request("DELETE", &format!("{S}/grants/{}", id_of(&grant)), t, None)
        }
        // ── teams, positions, organizations ─────────────────────────────────
        "POST /api/v1/admin/security/teams" => request(
            "POST",
            &format!("{S}/teams"),
            t,
            Some(json!({"name": uniq("team")})),
        ),
        "DELETE /api/v1/admin/security/teams/{id}" => {
            let id = team(fx).await;
            request("DELETE", &format!("{S}/teams/{id}"), t, None)
        }
        "POST /api/v1/admin/security/teams/{id}/members" => {
            let id = team(fx).await;
            let (_, email) = seed_user(&fx.base, "member").await;
            request(
                "POST",
                &format!("{S}/teams/{id}/members"),
                t,
                Some(json!({"user_email": email})),
            )
        }
        "DELETE /api/v1/admin/security/teams/{id}/members/{user_id}" => {
            let id = team(fx).await;
            let (user, email) = seed_user(&fx.base, "member").await;
            admin(
                fx,
                "POST",
                &format!("{S}/teams/{id}/members"),
                Some(json!({"user_email": email})),
            )
            .await;
            request("DELETE", &format!("{S}/teams/{id}/members/{user}"), t, None)
        }
        "POST /api/v1/admin/security/teams/{id}/roles" => {
            let id = team(fx).await;
            let rid = role(fx).await;
            request(
                "POST",
                &format!("{S}/teams/{id}/roles"),
                t,
                Some(json!({"role_id": rid})),
            )
        }
        "DELETE /api/v1/admin/security/teams/{id}/roles/{role_id}" => {
            let id = team(fx).await;
            let rid = role(fx).await;
            admin(
                fx,
                "POST",
                &format!("{S}/teams/{id}/roles"),
                Some(json!({"role_id": rid})),
            )
            .await;
            request("DELETE", &format!("{S}/teams/{id}/roles/{rid}"), t, None)
        }
        "POST /api/v1/admin/security/positions" => request(
            "POST",
            &format!("{S}/positions"),
            t,
            Some(json!({"name": uniq("position")})),
        ),
        "PUT /api/v1/admin/security/positions/{id}/parent" => {
            let child = position(fx).await;
            let parent = position(fx).await;
            request(
                "PUT",
                &format!("{S}/positions/{child}/parent"),
                t,
                Some(json!({"parent_position_id": parent})),
            )
        }
        "DELETE /api/v1/admin/security/positions/{id}" => {
            let id = position(fx).await;
            request("DELETE", &format!("{S}/positions/{id}"), t, None)
        }
        "POST /api/v1/admin/security/positions/{id}/members" => {
            let id = position(fx).await;
            let (_, email) = seed_user(&fx.base, "holder").await;
            request(
                "POST",
                &format!("{S}/positions/{id}/members"),
                t,
                Some(json!({"user_email": email})),
            )
        }
        "DELETE /api/v1/admin/security/positions/{id}/members/{user_id}" => {
            let id = position(fx).await;
            let (user, email) = seed_user(&fx.base, "holder").await;
            admin(
                fx,
                "POST",
                &format!("{S}/positions/{id}/members"),
                Some(json!({"user_email": email})),
            )
            .await;
            request(
                "DELETE",
                &format!("{S}/positions/{id}/members/{user}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/security/organizations/{id}/members" => {
            let id = organization(fx).await;
            let (_, email) = seed_user(&fx.base, "org-member").await;
            request(
                "POST",
                &format!("{S}/organizations/{id}/members"),
                t,
                Some(json!({"user_email": email})),
            )
        }
        "DELETE /api/v1/admin/security/organizations/{id}/members/{user_id}" => {
            let id = organization(fx).await;
            let (user, email) = seed_user(&fx.base, "org-member").await;
            admin(
                fx,
                "POST",
                &format!("{S}/organizations/{id}/members"),
                Some(json!({"user_email": email})),
            )
            .await;
            request(
                "DELETE",
                &format!("{S}/organizations/{id}/members/{user}"),
                t,
                None,
            )
        }
        // ── field security ──────────────────────────────────────────────────
        "POST /api/v1/admin/security/field-profiles" => request(
            "POST",
            &format!("{S}/field-profiles"),
            t,
            Some(json!({"name": uniq("profile")})),
        ),
        "POST /api/v1/admin/security/field-profiles/{id}/fields" => {
            let id = field_profile(fx).await;
            request(
                "POST",
                &format!("{S}/field-profiles/{id}/fields"),
                t,
                Some(json!({
                    "entity_logicalname": fx.entity,
                    "field_logicalname": "title",
                    "can_read": true,
                })),
            )
        }
        "POST /api/v1/admin/security/field-profiles/{id}/assignments" => {
            let id = field_profile(fx).await;
            let rid = role(fx).await;
            request(
                "POST",
                &format!("{S}/field-profiles/{id}/assignments"),
                t,
                Some(json!({"role_id": rid})),
            )
        }
        "DELETE /api/v1/admin/security/field-profiles/{id}/assignments/{role_id}" => {
            let id = field_profile(fx).await;
            let rid = role(fx).await;
            admin(
                fx,
                "POST",
                &format!("{S}/field-profiles/{id}/assignments"),
                Some(json!({"role_id": rid})),
            )
            .await;
            request(
                "DELETE",
                &format!("{S}/field-profiles/{id}/assignments/{rid}"),
                t,
                None,
            )
        }
        // ── shares ──────────────────────────────────────────────────────────
        "POST /api/v1/admin/security/record-shares" => {
            let (_, email) = seed_user(&fx.base, "sharee").await;
            request(
                "POST",
                &format!("{S}/record-shares"),
                t,
                Some(json!({
                    "entity": fx.entity, "record_id": fx.record_id,
                    "capability": "view", "user_email": email,
                })),
            )
        }
        "PUT /api/v1/admin/security/record-shares/reassign-owner" => {
            let (_, email) = seed_user(&fx.base, "new-owner").await;
            request(
                "PUT",
                &format!("{S}/record-shares/reassign-owner"),
                t,
                Some(json!({"entity": fx.entity, "record_id": fx.record_id, "user_email": email})),
            )
        }
        "DELETE /api/v1/admin/security/record-shares/{id}" => {
            let (_, email) = seed_user(&fx.base, "sharee").await;
            let share = admin(
                fx,
                "POST",
                &format!("{S}/record-shares"),
                Some(json!({
                    "entity": fx.entity, "record_id": fx.record_id,
                    "capability": "view", "user_email": email,
                })),
            )
            .await;
            request(
                "DELETE",
                &format!("{S}/record-shares/{}", id_of(&share)),
                t,
                None,
            )
        }
        "POST /api/v1/admin/security/entity-default-shares" => {
            let (_, email) = seed_user(&fx.base, "default-sharee").await;
            request(
                "POST",
                &format!("{S}/entity-default-shares"),
                t,
                Some(json!({"entity": fx.entity, "capability": "view", "user_email": email})),
            )
        }
        "DELETE /api/v1/admin/security/entity-default-shares/{id}" => {
            let (_, email) = seed_user(&fx.base, "default-sharee").await;
            let share = admin(
                fx,
                "POST",
                &format!("{S}/entity-default-shares"),
                Some(json!({"entity": fx.entity, "capability": "view", "user_email": email})),
            )
            .await;
            request(
                "DELETE",
                &format!("{S}/entity-default-shares/{}", id_of(&share)),
                t,
                None,
            )
        }
        // ── access reviews ──────────────────────────────────────────────────
        "POST /api/v1/admin/security/access-reviews" => {
            let rid = role(fx).await;
            request(
                "POST",
                &format!("{S}/access-reviews"),
                t,
                Some(json!({
                    "name": uniq("review"), "scope": "role", "scope_role_id": rid,
                    "due_date": chrono::Utc::now() + chrono::Duration::days(7),
                })),
            )
        }
        "POST /api/v1/admin/security/access-reviews/{id}/items/{item_id}/decide" => {
            let rid = role(fx).await;
            let (subject, _) = seed_user(&fx.base, "reviewed").await;
            admin(
                fx,
                "POST",
                &format!("{S}/users/{subject}/roles"),
                Some(json!({"role_id": rid})),
            )
            .await;
            let review = admin(
                fx,
                "POST",
                &format!("{S}/access-reviews"),
                Some(json!({
                    "name": uniq("review"), "scope": "role", "scope_role_id": rid,
                    "due_date": chrono::Utc::now() + chrono::Duration::days(7),
                })),
            )
            .await;
            let review_id = id_of(&review);
            let item: Uuid = sqlx::query_scalar(
                "SELECT id FROM access_review_item WHERE review_ref = $1 LIMIT 1",
            )
            .bind(review_id)
            .fetch_one(&fx.base.db)
            .await
            .expect("the campaign has an item for the role holder");
            request(
                "POST",
                &format!("{S}/access-reviews/{review_id}/items/{item}/decide"),
                t,
                Some(json!({"decision": "keep"})),
            )
        }
        // ── account state, sessions, MFA reset ──────────────────────────────
        "POST /api/v1/admin/security/users/{id}/disable" => {
            let (user, _) = seed_user(&fx.base, "disabled").await;
            request("POST", &format!("{S}/users/{user}/disable"), t, None)
        }
        "POST /api/v1/admin/security/users/{id}/enable" => {
            let (user, _) = seed_user(&fx.base, "enabled").await;
            request("POST", &format!("{S}/users/{user}/enable"), t, None)
        }
        "POST /api/v1/admin/security/sessions/revoke" => request(
            "POST",
            &format!("{S}/sessions/revoke"),
            t,
            Some(json!({"jti": Uuid::now_v7()})),
        ),
        "POST /api/v1/admin/security/users/{id}/mfa/reset" => {
            let (user, _) = enrolled_user(fx, "mfa-reset").await;
            request("POST", &format!("{S}/users/{user}/mfa/reset"), t, None)
        }
        // ── devices (B17-T4) ────────────────────────────────────────────────
        "POST /api/v1/devices" => request(
            "POST",
            "/api/v1/devices",
            t,
            Some(json!({"platform": "web", "app_kind": "pwa", "app_version": "1.0.0"})),
        ),
        "POST /api/v1/devices/me/{id}/wiped" => {
            // The admin's own device with a wipe already pending (seeded, so
            // the admin's sessions are not ended by a wipe request).
            let device: Uuid = sqlx::query_scalar(
                "INSERT INTO user_device (user_id, platform, app_kind, app_version, wipe_requested_at)                  VALUES ($1, 'ios', 'standard', '1.0.0', now()) RETURNING id",
            )
            .bind(fx.admin_id)
            .fetch_one(&fx.base.db)
            .await
            .expect("seed a device awaiting its wipe");
            request(
                "POST",
                &format!("/api/v1/devices/me/{device}/wiped"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/devices/{id}/wipe" => {
            // Another person's device, so the wipe ends their sessions only.
            let (user, _) = seed_user(&fx.base, "device-owner").await;
            let device: Uuid = sqlx::query_scalar(
                "INSERT INTO user_device (user_id, platform, app_kind, app_version)                  VALUES ($1, 'android', 'standard', '1.0.0') RETURNING id",
            )
            .bind(user)
            .fetch_one(&fx.base.db)
            .await
            .expect("seed a device");
            request(
                "POST",
                &format!("/api/v1/admin/devices/{device}/wipe"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/devices/{id}/offline-refresh" => {
            // B18-T12: a device that has synced once.
            let device: Uuid = sqlx::query_scalar(
                "INSERT INTO user_device (user_id, platform, app_kind, app_version) \
                 VALUES ($1, 'android', 'standard', '1.0.0') RETURNING id",
            )
            .bind(fx.admin_id)
            .fetch_one(&fx.base.db)
            .await
            .expect("seed a device");
            sqlx::query("INSERT INTO offline_device_state (device_id, profile_id) VALUES ($1, $2)")
                .bind(device)
                .bind(Uuid::now_v7())
                .execute(&fx.base.db)
                .await
                .expect("seed its sync state");
            request(
                "POST",
                &format!("/api/v1/admin/devices/{device}/offline-refresh"),
                t,
                None,
            )
        }
        // ── invitations, identity links ─────────────────────────────────────
        "POST /api/v1/admin/security/invitations" => request(
            "POST",
            &format!("{S}/invitations"),
            t,
            Some(json!({"email": format!("{}@example.test", uniq("invitee"))})),
        ),
        "DELETE /api/v1/admin/security/invitations/{id}" => {
            let created = admin(
                fx,
                "POST",
                &format!("{S}/invitations"),
                Some(json!({"email": format!("{}@example.test", uniq("invitee"))})),
            )
            .await;
            let id = id_of(&created);
            request("DELETE", &format!("{S}/invitations/{id}"), t, None)
        }
        "POST /api/v1/admin/security/identity-links" => {
            let (user, _) = seed_user(&fx.base, "linked").await;
            request(
                "POST",
                &format!("{S}/identity-links"),
                t,
                Some(
                    json!({"provider_key": "emission-idp", "provider_sub": uniq("sub"), "user_ref": user}),
                ),
            )
        }
        // ── API keys and self-service MFA ───────────────────────────────────
        "POST /api/v1/auth/api-keys" => request(
            "POST",
            "/api/v1/auth/api-keys",
            Some(&fx.admin_token),
            Some(json!({"name": uniq("key")})),
        ),
        // ── notification preferences (U5, D-602) ────────────────────────────
        "PUT /api/v1/me/notification-preferences" => {
            let (user, _) = seed_user(&fx.base, "notification-prefs").await;
            let token = session_token(&fx.base, user, false).await;
            request(
                "PUT",
                "/api/v1/me/notification-preferences",
                Some(&token),
                Some(json!({"items": [
                    {"category": "reminder", "channel": "email", "enabled": false}
                ]})),
            )
        }
        "DELETE /api/v1/auth/api-keys/{id}" => {
            let key = admin(
                fx,
                "POST",
                "/api/v1/auth/api-keys",
                Some(json!({"name": uniq("key")})),
            )
            .await;
            request(
                "DELETE",
                &format!("/api/v1/auth/api-keys/{}", id_of(&key)),
                t,
                None,
            )
        }
        "POST /api/v1/auth/mfa/confirm" => {
            let (user, _) = seed_user(&fx.base, "mfa-confirm").await;
            let token = session_token(&fx.base, user, false).await;
            let ring = fx.base.secrets.load().mfa_encryption_key.clone();
            let enrolled = attome_auth::mfa::enroll(&fx.base.db, &ring, user)
                .await
                .expect("enroll");
            let code = totp_for(&enrolled.secret_base32)
                .generate_current()
                .to_string();
            request(
                "POST",
                "/api/v1/auth/mfa/confirm",
                Some(&token),
                Some(json!({"code": code})),
            )
        }
        "POST /api/v1/auth/mfa/disable" => {
            let (user, totp) = enrolled_user(fx, "mfa-disable").await;
            let token = session_token(&fx.base, user, false).await;
            request(
                "POST",
                "/api/v1/auth/mfa/disable",
                Some(&token),
                Some(json!({"code": code_at_offset(&totp, 30)})),
            )
        }
        "POST /api/v1/auth/mfa/recovery-codes/regenerate" => {
            let (user, totp) = enrolled_user(fx, "mfa-regen").await;
            let token = session_token(&fx.base, user, false).await;
            request(
                "POST",
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                Some(&token),
                Some(json!({"code": code_at_offset(&totp, 30)})),
            )
        }
        // ── S2S ─────────────────────────────────────────────────────────────
        "POST /api/v1/admin/s2s/clients" => {
            let (service_user, _) = seed_user(&fx.base, "s2s-service").await;
            request(
                "POST",
                "/api/v1/admin/s2s/clients",
                t,
                Some(json!({
                    "client_id": uniq("client"), "name": "audit emission client",
                    "service_user_ref": service_user,
                })),
            )
        }
        "PATCH /api/v1/admin/s2s/clients/{client_db_id}" => {
            let id = s2s_client(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/admin/s2s/clients/{id}"),
                t,
                Some(json!({"name": "renamed", "row_version": 0})),
            )
        }
        "DELETE /api/v1/admin/s2s/clients/{client_db_id}" => {
            let id = s2s_client(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/s2s/clients/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/s2s/clients/{client_db_id}/keys" => {
            let id = s2s_client(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/s2s/clients/{id}/keys"),
                t,
                Some(json!({"slot": "primary"})),
            )
        }
        "DELETE /api/v1/admin/s2s/clients/{client_db_id}/keys/{slot}" => {
            let id = s2s_client(fx).await;
            admin(
                fx,
                "POST",
                &format!("/api/v1/admin/s2s/clients/{id}/keys"),
                Some(json!({"slot": "primary"})),
            )
            .await;
            request(
                "DELETE",
                &format!("/api/v1/admin/s2s/clients/{id}/keys/primary"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/s2s/clients/{client_db_id}/permissions" => {
            let id = s2s_client(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/s2s/clients/{id}/permissions"),
                t,
                Some(json!({"entity_name": "role", "can_read": true})),
            )
        }
        "DELETE /api/v1/admin/s2s/clients/{client_db_id}/permissions/{entity_name}" => {
            let id = s2s_client(fx).await;
            admin(
                fx,
                "POST",
                &format!("/api/v1/admin/s2s/clients/{id}/permissions"),
                Some(json!({"entity_name": "role", "can_read": true})),
            )
            .await;
            request(
                "DELETE",
                &format!("/api/v1/admin/s2s/clients/{id}/permissions/role"),
                t,
                None,
            )
        }
        // ── web portals (D-576) ─────────────────────────────────────────────
        "POST /api/v1/admin/webportals" => request(
            "POST",
            "/api/v1/admin/webportals",
            t,
            Some(json!({
                "name": "audit emission portal",
                "keyword": portal_keyword(),
                "portal_type": "authenticated",
            })),
        ),
        "PATCH /api/v1/admin/webportals/{id}/settings" => {
            let portal = webportal(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/admin/webportals/{}/settings", id_of(&portal)),
                t,
                Some(json!({"row_version": portal["row_version"], "is_enabled": false})),
            )
        }
        "POST /api/v1/admin/webportals/{id}/users" => {
            let portal = id_of(&webportal(fx).await);
            request(
                "POST",
                &format!("/api/v1/admin/webportals/{portal}/users"),
                t,
                Some(json!({"name": "Ada", "email": format!("{}@example.com", uniq("portal"))})),
            )
        }
        "POST /api/v1/admin/webportals/{id}/users/{user_id}/disable" => {
            let (portal, user) = webportal_user(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/webportals/{portal}/users/{user}/disable"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/webportals/{id}/users/{user_id}/enable" => {
            let (portal, user) = webportal_user(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/webportals/{portal}/users/{user}/enable"),
                t,
                None,
            )
        }
        "DELETE /api/v1/admin/webportals/{id}/users/{user_id}" => {
            let (portal, user) = webportal_user(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/webportals/{portal}/users/{user}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/webportals/{id}/users/{user_id}/invite" => {
            let (portal, user, _) = portal_with_invited_user(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/webportals/{}/users/{user}/invite", portal.id),
                t,
                None,
            )
        }

        // ── web portal roles and grants (D-574, D-575, D-579) ──────────────
        "POST /api/v1/admin/webportals/{id}/roles" => {
            let (portal, _, _) = portal_with_invited_user(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/webportals/{}/roles", portal.id),
                t,
                Some(json!({"name": uniq("role")})),
            )
        }
        "PUT /api/v1/admin/webportals/{id}/roles/{role_id}/grants/{entity}" => {
            let (portal, role) = portal_role(fx).await;
            request(
                "PUT",
                &format!(
                    "/api/v1/admin/webportals/{portal}/roles/{role}/grants/{}",
                    fx.entity
                ),
                t,
                Some(portal_grant_body()),
            )
        }
        "DELETE /api/v1/admin/webportals/{id}/roles/{role_id}/grants/{entity}" => {
            let (portal, role) = portal_role(fx).await;
            let uri = format!(
                "/api/v1/admin/webportals/{portal}/roles/{role}/grants/{}",
                fx.entity
            );
            let res = fx
                .app
                .clone()
                .oneshot(request("PUT", &uri, t, Some(portal_grant_body())))
                .await
                .expect("grant");
            assert!(res.status().is_success(), "grant: {}", res.status());
            request("DELETE", &uri, t, None)
        }
        "PUT /api/v1/admin/webportals/{id}/users/{user_id}/role" => {
            let (portal, role) = portal_role(fx).await;
            let user = admin(
                fx,
                "POST",
                &format!("/api/v1/admin/webportals/{portal}/users"),
                Some(json!({"name": "Ada", "email": format!("{}@example.com", uniq("portal"))})),
            )
            .await;
            request(
                "PUT",
                &format!(
                    "/api/v1/admin/webportals/{portal}/users/{}/role",
                    id_of(&user)
                ),
                t,
                Some(json!({"role_id": role})),
            )
        }
        // ── web portal admin lifecycle (plan §9.5 G-8, G-14) ────────────────
        "PATCH /api/v1/admin/webportals/{id}/roles/{role_id}" => {
            let (portal, role) = portal_role(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/admin/webportals/{portal}/roles/{role}"),
                t,
                Some(json!({"name": uniq("renamed")})),
            )
        }
        "DELETE /api/v1/admin/webportals/{id}/roles/{role_id}" => {
            let (portal, role) = portal_role(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/webportals/{portal}/roles/{role}"),
                t,
                None,
            )
        }
        "DELETE /api/v1/admin/webportals/{id}/users/{user_id}/role" => {
            let (portal, role) = portal_role(fx).await;
            let user = admin(
                fx,
                "POST",
                &format!("/api/v1/admin/webportals/{portal}/users"),
                Some(json!({"name": "Ada", "email": format!("{}@example.com", uniq("portal"))})),
            )
            .await;
            admin(
                fx,
                "PUT",
                &format!(
                    "/api/v1/admin/webportals/{portal}/users/{}/role",
                    id_of(&user)
                ),
                Some(json!({"role_id": role})),
            )
            .await;
            request(
                "DELETE",
                &format!(
                    "/api/v1/admin/webportals/{portal}/users/{}/role",
                    id_of(&user)
                ),
                t,
                None,
            )
        }
        "POST /api/v1/admin/webportals/{id}/users/{user_id}/erase" => {
            let (portal, user, _) = portal_with_active_user(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/webportals/{}/users/{user}/erase", portal.id),
                t,
                None,
            )
        }
        "POST /api/v1/admin/webportals/{id}/erasure-requests/{request_id}/reject" => {
            let (portal, user, _) = portal_with_active_user(fx).await;
            let request_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO webportal_erasure_request (id, webportal_id, webportal_user_id) VALUES ($1, $2, $3)",
            )
            .bind(request_id)
            .bind(portal.id)
            .bind(user)
            .execute(&fx.base.db)
            .await
            .expect("open an erasure request");
            request(
                "POST",
                &format!(
                    "/api/v1/admin/webportals/{}/erasure-requests/{request_id}/reject",
                    portal.id
                ),
                t,
                None,
            )
        }
        "PUT /api/v1/admin/webportals/{id}/entities/{entity}" => {
            let (portal, _, _) = portal_with_invited_user(fx).await;
            request(
                "PUT",
                &format!(
                    "/api/v1/admin/webportals/{}/entities/{}",
                    portal.id, fx.entity
                ),
                t,
                Some(json!({"portal_user_field": null})),
            )
        }

        // ── web portal authentication (D-573, the portal's own router) ──────
        "POST /{keyword}/api/v1/auth/login" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            request(
                "POST",
                &format!("/{}/api/v1/auth/login", portal.keyword),
                None,
                Some(json!({"email": email, "password": PASSWORD})),
            )
        }
        // The primary event is `SessionRevoked`, written on refresh-token
        // reuse: rotate once, then present the consumed token again.
        "POST /{keyword}/api/v1/auth/refresh" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            let refresh_cookie: Vec<String> = cookies
                .iter()
                .filter(|c| c.contains("_refresh="))
                .cloned()
                .collect();
            let rotated = fx
                .app
                .clone()
                .oneshot(with_cookies(
                    request(
                        "POST",
                        &format!("/{}/api/v1/auth/refresh", portal.keyword),
                        None,
                        None,
                    ),
                    &refresh_cookie,
                ))
                .await
                .expect("first refresh");
            assert!(
                rotated.status().is_success(),
                "first refresh: {}",
                rotated.status()
            );
            return Some((
                with_cookies(
                    request(
                        "POST",
                        &format!("/{}/api/v1/auth/refresh", portal.keyword),
                        None,
                        None,
                    ),
                    &refresh_cookie,
                ),
                Some(StatusCode::UNAUTHORIZED),
            ));
        }
        "POST /{keyword}/api/v1/auth/logout" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/auth/logout", portal.keyword),
                    None,
                    None,
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/auth/invitation/accept" => {
            let (portal, user, _) = portal_with_invited_user(fx).await;
            let mut tx = fx.base.db.begin().await.expect("begin");
            let (_, invitation) = attome_portal::auth::issue_invitation(
                &mut tx,
                &fx.base.pepper_ring(),
                portal.id,
                user,
            )
            .await
            .expect("issue invitation")
            .expect("invited user");
            tx.commit().await.expect("commit");
            request(
                "POST",
                &format!("/{}/api/v1/auth/invitation/accept", portal.keyword),
                None,
                Some(json!({"token": invitation.bearer, "password": PASSWORD})),
            )
        }
        "POST /{keyword}/api/v1/auth/reset-request" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            request(
                "POST",
                &format!("/{}/api/v1/auth/reset-request", portal.keyword),
                None,
                Some(json!({"email": email})),
            )
        }
        "POST /{keyword}/api/v1/auth/reset-confirm" => {
            let (portal, user, _) = portal_with_active_user(fx).await;
            let mut tx = fx.base.db.begin().await.expect("begin");
            let token = attome_portal::onetime::issue(
                &mut tx,
                &fx.base.pepper_ring(),
                attome_portal::onetime::Kind::Reset,
                portal.id,
                user,
            )
            .await
            .expect("issue reset");
            tx.commit().await.expect("commit");
            request(
                "POST",
                &format!("/{}/api/v1/auth/reset-confirm", portal.keyword),
                None,
                Some(json!({"token": token.bearer, "password": "a-new-portal-password-1"})),
            )
        }
        "POST /{keyword}/api/v1/auth/mfa/enroll" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/auth/mfa/enroll", portal.keyword),
                    None,
                    None,
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/auth/mfa/confirm" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            let enrolled = call(
                fx,
                with_cookies(
                    request(
                        "POST",
                        &format!("/{}/api/v1/auth/mfa/enroll", portal.keyword),
                        None,
                        None,
                    ),
                    &cookies,
                ),
            )
            .await;
            let secret = enrolled["secret"].as_str().expect("secret");
            let now = u64::try_from(chrono::Utc::now().timestamp()).expect("time");
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/auth/mfa/confirm", portal.keyword),
                    None,
                    Some(json!({"code": attome_portal::mfa::code_at(secret, now).expect("code")})),
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/auth/signup" => {
            let (portal, _, _) = portal_with_invited_user(fx).await;
            request(
                "POST",
                &format!("/{}/api/v1/auth/signup", portal.keyword),
                None,
                Some(json!({
                    "name": "Signup",
                    "email": format!("{}@example.com", uniq("signup")),
                    "password": PASSWORD,
                })),
            )
        }
        "POST /{keyword}/api/v1/auth/signup/verify" => {
            let (portal, _, _) = portal_with_invited_user(fx).await;
            let role = admin(
                fx,
                "POST",
                &format!("/api/v1/admin/webportals/{}/roles", portal.id),
                Some(json!({"name": uniq("signup-role")})),
            )
            .await;
            let mut tx = fx.base.db.begin().await.expect("begin");
            let policy = attome_portal::policy::save(
                &mut tx,
                portal.id,
                &attome_portal::policy::AuthPolicy {
                    signup_mode: attome_portal::policy::SignupMode::SelfService,
                    signup_role_ref: Some(id_of(&role)),
                    ..Default::default()
                },
                &[],
                &[],
            )
            .await
            .expect("save policy");
            let hash = attome_auth::hash_password_async(
                attome_auth::NewPassword::platform_generated(PASSWORD),
            )
            .await
            .expect("hash");
            let email = format!("{}@example.com", uniq("verify"));
            let attome_portal::signup::SignupRequest::Pending { bearer } =
                attome_portal::signup::request(
                    &mut tx,
                    &fx.base.pepper_ring(),
                    &portal,
                    &policy,
                    &attome_portal::signup::SignupInput {
                        name: "Verify",
                        email_lower: &email,
                        password_hash: &hash,
                        terms_version: None,
                        privacy_version: None,
                    },
                )
                .await
                .expect("signup request")
            else {
                panic!("expected a pending signup");
            };
            tx.commit().await.expect("commit");
            request(
                "POST",
                &format!("/{}/api/v1/auth/signup/verify", portal.keyword),
                None,
                Some(json!({"token": bearer})),
            )
        }
        "POST /{keyword}/api/v1/auth/email/verify" => {
            let (portal, user, _) = portal_with_active_user(fx).await;
            let email = format!("{}@example.com", uniq("added"));
            let mut tx = fx.base.db.begin().await.expect("begin");
            let token = attome_portal::onetime::issue_email_add(
                &mut tx,
                &fx.base.pepper_ring(),
                portal.id,
                user,
                &email,
            )
            .await
            .expect("issue email-add link");
            tx.commit().await.expect("commit");
            request(
                "POST",
                &format!("/{}/api/v1/auth/email/verify", portal.keyword),
                None,
                Some(json!({"token": token.bearer})),
            )
        }
        "POST /{keyword}/api/v1/me/consent" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let mut tx = fx.base.db.begin().await.expect("begin");
            attome_portal::policy::save(
                &mut tx,
                portal.id,
                &attome_portal::policy::AuthPolicy {
                    terms_version: Some("v1".into()),
                    ..Default::default()
                },
                &[],
                &[],
            )
            .await
            .expect("save policy");
            tx.commit().await.expect("commit");
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/me/consent", portal.keyword),
                    None,
                    Some(json!({"terms_version": "v1"})),
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/me/password" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/me/password", portal.keyword),
                    None,
                    Some(json!({
                        "current_password": PASSWORD,
                        "new_password": "a-new-portal-password-2",
                    })),
                ),
                &cookies,
            )
        }
        "DELETE /{keyword}/api/v1/me/sessions/{id}" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let _other = portal_login(fx, &portal.keyword, &email).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            let sessions = call(
                fx,
                with_cookies(
                    request(
                        "GET",
                        &format!("/{}/api/v1/me/sessions", portal.keyword),
                        None,
                        None,
                    ),
                    &cookies,
                ),
            )
            .await;
            let other = sessions
                .as_array()
                .expect("session list")
                .iter()
                .find(|s| s["current"] == false)
                .expect("the other session");
            let other_id = other["id"].as_str().expect("id").to_owned();
            with_cookies(
                request(
                    "DELETE",
                    &format!("/{}/api/v1/me/sessions/{other_id}", portal.keyword),
                    None,
                    None,
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/me/sessions/end-others" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/me/sessions/end-others", portal.keyword),
                    None,
                    None,
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/me/erasure-request" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/me/erasure-request", portal.keyword),
                    None,
                    None,
                ),
                &cookies,
            )
        }
        "PUT /api/v1/admin/webportals/{id}/auth-policy" => {
            let (portal, _, _) = portal_with_invited_user(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/webportals/{}/auth-policy", portal.id),
                Some(&fx.admin_token),
                Some(json!({"signup_mode": "invite_only"})),
            )
        }
        "PUT /api/v1/admin/security/roles/{id}/bulk-fields" => {
            let id = role(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/security/roles/{id}/bulk-fields"),
                Some(&fx.admin_token),
                Some(json!({"mode": "legacy", "fields": []})),
            )
        }
        "POST /{keyword}/api/v1/auth/oidc/link" => {
            let (portal, user, _) = portal_with_active_user(fx).await;
            let pending = attome_portal::oidc::store_pending(
                &fx.base.redis_coordination,
                &attome_portal::oidc::Pending {
                    kind: attome_portal::oidc::PendingKind::Link,
                    webportal_id: portal.id,
                    user_id: user,
                    provider: "test".into(),
                    issuer: "https://idp.test".into(),
                    subject: uniq("sub"),
                },
            )
            .await
            .expect("stage pending link");
            request(
                "POST",
                &format!("/{}/api/v1/auth/oidc/link", portal.keyword),
                None,
                Some(json!({"pending": pending, "password": PASSWORD})),
            )
        }
        "POST /{keyword}/api/v1/auth/oidc/mfa" => {
            let (portal, user, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            let (secret, confirmed_at) = portal_enroll_mfa(fx, &portal.keyword, &cookies).await;
            let pending = attome_portal::oidc::store_pending(
                &fx.base.redis_coordination,
                &attome_portal::oidc::Pending {
                    kind: attome_portal::oidc::PendingKind::Mfa,
                    webportal_id: portal.id,
                    user_id: user,
                    provider: "test".into(),
                    issuer: "https://idp.test".into(),
                    subject: uniq("sub"),
                },
            )
            .await
            .expect("stage pending mfa");
            let code = attome_portal::mfa::code_at(&secret, confirmed_at + 30).expect("code");
            request(
                "POST",
                &format!("/{}/api/v1/auth/oidc/mfa", portal.keyword),
                None,
                Some(json!({"pending": pending, "code": code})),
            )
        }
        "POST /{keyword}/api/v1/auth/mfa/recovery-codes" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            let (secret, confirmed_at) = portal_enroll_mfa(fx, &portal.keyword, &cookies).await;
            let code = attome_portal::mfa::code_at(&secret, confirmed_at + 30).expect("code");
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/auth/mfa/recovery-codes", portal.keyword),
                    None,
                    Some(json!({"code": code})),
                ),
                &cookies,
            )
        }
        "POST /{keyword}/api/v1/auth/mfa/disable" => {
            let (portal, _, email) = portal_with_active_user(fx).await;
            let cookies = portal_login(fx, &portal.keyword, &email).await;
            let (secret, confirmed_at) = portal_enroll_mfa(fx, &portal.keyword, &cookies).await;
            // The confirming step is spent; the next one is accepted.
            let code = attome_portal::mfa::code_at(&secret, confirmed_at + 30).expect("code");
            with_cookies(
                request(
                    "POST",
                    &format!("/{}/api/v1/auth/mfa/disable", portal.keyword),
                    None,
                    Some(json!({"code": code})),
                ),
                &cookies,
            )
        }

        // ── authentication ──────────────────────────────────────────────────
        "POST /api/v1/auth/login" => {
            let (_, email) = seed_user(&fx.base, "login").await;
            request(
                "POST",
                "/api/v1/auth/login",
                None,
                Some(json!({"email": email, "password": PASSWORD})),
            )
        }
        "POST /api/v1/auth/logout" => {
            let (_, email) = seed_user(&fx.base, "logout").await;
            let cookies = login_cookies(fx, &email).await;
            with_cookies(
                request("POST", "/api/v1/auth/logout", None, Some(json!({}))),
                &cookies,
            )
        }
        "POST /api/v1/auth/refresh" => {
            // Rotation writes nothing; presenting the rotated-away refresh
            // token again is reuse, which revokes the family.
            let (user_id, email) = seed_user(&fx.base, "refresh").await;
            let refresh: Vec<String> = login_cookies(fx, &email)
                .await
                .into_iter()
                .filter(|c| c.contains("refresh_token="))
                .collect();
            call(
                fx,
                with_cookies(
                    request("POST", "/api/v1/auth/refresh", None, Some(json!({}))),
                    &refresh,
                ),
            )
            .await;
            // D-626: a replay inside the grace window is a plain 401 that
            // revokes nothing; age the rotation past it to reach reuse.
            sqlx::query(
                "UPDATE refresh_token SET used_at = used_at - interval '11 seconds'
                 WHERE user_ref = $1 AND used_at IS NOT NULL",
            )
            .bind(user_id)
            .execute(&fx.base.db)
            .await
            .expect("age the rotation");
            let replay = with_cookies(
                request("POST", "/api/v1/auth/refresh", None, Some(json!({}))),
                &refresh,
            );
            return Some((replay, Some(StatusCode::UNAUTHORIZED)));
        }
        "POST /api/v1/auth/reset-request" => {
            let (_, email) = seed_user(&fx.base, "reset-request").await;
            request(
                "POST",
                "/api/v1/auth/reset-request",
                None,
                Some(json!({"email": email})),
            )
        }
        "POST /api/v1/auth/reset-confirm" => {
            let (_, email) = seed_user(&fx.base, "reset-confirm").await;
            let mut tx = attome_db::tx::begin(&fx.base.db).await.expect("begin");
            let issued =
                attome_auth::reset::request_in_tx(&mut tx, &email, 30, &fx.base.pepper_ring())
                    .await
                    .expect("mint reset token")
                    .expect("known account");
            tx.commit().await.expect("commit");
            request(
                "POST",
                "/api/v1/auth/reset-confirm",
                None,
                Some(json!({"token": issued.bearer, "new_password": "a-brand-new-password-9"})),
            )
        }
        "POST /api/v1/auth/mfa/verify" => {
            let (user, totp) = enrolled_user(fx, "mfa-verify").await;
            let token = pending_token(fx, user, attome_auth::TokenType::MfaPendingLogin).await;
            request(
                "POST",
                "/api/v1/auth/mfa/verify",
                None,
                Some(json!({"pending_token": token, "code": code_at_offset(&totp, 30)})),
            )
        }
        "POST /api/v1/auth/mfa/verify-recovery" => {
            let (user, _, codes) = enrolled_user_with_codes(fx, "mfa-recovery").await;
            let token = pending_token(fx, user, attome_auth::TokenType::MfaPendingLogin).await;
            request(
                "POST",
                "/api/v1/auth/mfa/verify-recovery",
                None,
                Some(json!({"pending_token": token, "code": codes[0]})),
            )
        }
        "POST /api/v1/auth/mfa/pending-confirm" => {
            let (user, _) = seed_user(&fx.base, "mfa-forced").await;
            let token = pending_token(fx, user, attome_auth::TokenType::MfaPendingEnroll).await;
            let enrolled = attome_auth::mfa::enroll_pending(
                &fx.base.db,
                &fx.base.secrets.load().mfa_encryption_key,
                &token,
                &fx.base.secrets.load().jwt_secret,
                &fx.base.config.auth.jwt_issuer,
                fx.base.config.jwt_audience(),
            )
            .await
            .expect("pending enroll");
            let code = totp_for(&enrolled.secret_base32)
                .generate_current()
                .to_string();
            request(
                "POST",
                "/api/v1/auth/mfa/pending-confirm",
                None,
                Some(json!({"pending_token": token, "code": code})),
            )
        }
        "POST /api/v1/auth/register" => request(
            "POST",
            "/api/v1/auth/register",
            None,
            Some(json!({
                "email": format!("{}@example.test", uniq("registered")),
                "password": PASSWORD,
            })),
        ),
        "POST /api/v1/auth/verify-email/confirm" => {
            let (user, _) = seed_user(&fx.base, "verify-email").await;
            let issued =
                attome_auth::verification::request(&fx.base.db, user, 24, &fx.base.pepper_ring())
                    .await
                    .expect("mint verification token");
            request(
                "POST",
                "/api/v1/auth/verify-email/confirm",
                None,
                Some(json!({"token": issued.bearer})),
            )
        }
        "POST /api/v1/auth/mfa/enroll" => {
            let (user, _) = seed_user(&fx.base, "mfa-enroll").await;
            let token = session_token(&fx.base, user, false).await;
            request("POST", "/api/v1/auth/mfa/enroll", Some(&token), None)
        }
        "POST /api/v1/auth/mfa/pending-enroll" => {
            let (user, _) = seed_user(&fx.base, "mfa-pending-enroll").await;
            let token = pending_token(fx, user, attome_auth::TokenType::MfaPendingEnroll).await;
            request(
                "POST",
                "/api/v1/auth/mfa/pending-enroll",
                None,
                Some(json!({"pending_token": token})),
            )
        }
        "POST /api/v1/auth/step-up/{operation}/verify" => {
            let (user, _) = seed_user(&fx.base, "step-up").await;
            let token = session_token(&fx.base, user, false).await;
            let started = call(
                fx,
                request(
                    "POST",
                    "/api/v1/auth/step-up/identity_link",
                    Some(&token),
                    Some(json!({})),
                ),
            )
            .await;
            let challenge_id = started["challenge_id"]
                .as_str()
                .unwrap_or_else(|| panic!("step-up start returned no challenge_id: {started}"))
                .to_owned();
            request(
                "POST",
                "/api/v1/auth/step-up/identity_link/verify",
                Some(&token),
                Some(json!({
                    "challenge_id": challenge_id,
                    "factor": "password",
                    "credential": PASSWORD,
                })),
            )
        }
        // ── approvals ───────────────────────────────────────────────────────
        "POST /api/v1/admin/approval-policies" => request(
            "POST",
            "/api/v1/admin/approval-policies",
            t,
            Some(approval_policy_body(fx)),
        ),
        "PUT /api/v1/admin/approval-policies/{id}" => {
            let id = approval_policy(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/approval-policies/{id}"),
                t,
                Some(json!({"name": uniq("renamed-policy"), "row_version": 0})),
            )
        }
        "DELETE /api/v1/admin/approval-policies/{id}" => {
            let id = approval_policy(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/approval-policies/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/approvals/{id}/cancel" => {
            // Only the requester may cancel.
            let submitted = attome_approval::submit(
                &fx.base.db,
                &format!("audit_emit.{}", Uuid::now_v7().simple()),
                json!({}),
                fx.admin_id,
                1,
                chrono::Duration::hours(1),
            )
            .await
            .expect("submit approval request");
            request(
                "POST",
                &format!("/api/v1/admin/approvals/{}/cancel", submitted.id),
                t,
                Some(json!({"row_version": submitted.row_version})),
            )
        }
        "POST /api/v1/admin/approvals/{id}/decide" => {
            // A different requester (separation of duties); approving runs
            // the action inline, and a rewrap is a single job enqueue.
            let (requester, _) = seed_user(&fx.base, "approval-requester").await;
            let submitted = attome_approval::submit(
                &fx.base.db,
                attome_compliance::rewrap_admin::ACTION_SECURITY_REWRAP,
                json!({"domain": "mfa"}),
                requester,
                1,
                chrono::Duration::hours(1),
            )
            .await
            .expect("submit approval request");
            request(
                "POST",
                &format!("/api/v1/admin/approvals/{}/decide", submitted.id),
                t,
                Some(json!({"decision": "approve", "row_version": submitted.row_version})),
            )
        }
        "PUT /api/v1/approvals/out-of-office" => {
            // Z10-T7: the caller hands their approval standing to another user.
            let (delegate, _) = seed_user(&fx.base, "ooo-delegate").await;
            let from = chrono::Utc::now();
            request(
                "PUT",
                "/api/v1/approvals/out-of-office",
                t,
                Some(json!({
                    "to_user": delegate,
                    "valid_from": from,
                    "valid_to": from + chrono::Duration::days(7),
                })),
            )
        }
        "DELETE /api/v1/approvals/out-of-office" => {
            request("DELETE", "/api/v1/approvals/out-of-office", t, None)
        }
        "POST /api/v1/approvals/{id}/decide" => {
            // D-549 — the approver-facing route: a plan-bearing request whose
            // current step names the caller, by a different requester.
            // Approving runs the action inline (a rewrap is one job enqueue),
            // so every declared event — approval, digest, execution — is due.
            let (requester, _) = seed_user(&fx.base, "eligible-requester").await;
            let plan = attome_approval::ApprovalPlan {
                steps: vec![attome_approval::ApprovalStep {
                    mode: attome_approval::StepMode::Any,
                    threshold: None,
                    approvers: vec![format!("user:{}", fx.admin_id)],
                    sla_minutes: None,
                    on_timeout: attome_approval::OnTimeout::Escalate,
                    extras: Default::default(),
                }],
            };
            let submitted = attome_approval::submit_with_plan(
                &fx.base.db,
                attome_compliance::rewrap_admin::ACTION_SECURITY_REWRAP,
                json!({"domain": "mfa"}),
                requester,
                plan,
                chrono::Duration::hours(1),
                None,
            )
            .await
            .expect("submit plan-bearing approval request");
            request(
                "POST",
                &format!("/api/v1/approvals/{}/decide", submitted.id),
                t,
                Some(json!({"decision": "approve", "row_version": submitted.row_version})),
            )
        }
        "POST /api/v1/admin/approvals/{id}/delegate" => {
            // A plan-bearing request whose current step names the admin.
            let (requester, _) = seed_user(&fx.base, "delegation-requester").await;
            let (delegate, _) = seed_user(&fx.base, "delegate").await;
            let plan = attome_approval::ApprovalPlan {
                steps: vec![attome_approval::ApprovalStep {
                    mode: attome_approval::StepMode::Any,
                    threshold: None,
                    approvers: vec![format!("user:{}", fx.admin_id)],
                    sla_minutes: None,
                    on_timeout: attome_approval::OnTimeout::Escalate,
                    extras: Default::default(),
                }],
            };
            let submitted = attome_approval::submit_with_plan(
                &fx.base.db,
                &format!("audit_emit.{}", Uuid::now_v7().simple()),
                json!({}),
                requester,
                plan,
                chrono::Duration::hours(1),
                None,
            )
            .await
            .expect("submit plan-bearing approval request");
            request(
                "POST",
                &format!("/api/v1/admin/approvals/{}/delegate", submitted.id),
                t,
                Some(json!({"to_user_id": delegate})),
            )
        }
        // ── audit trail reads ───────────────────────────────────────────────
        "GET /api/v1/admin/audit/search" => {
            request("GET", "/api/v1/admin/audit/search?page_size=1", t, None)
        }
        "GET /api/v1/admin/audit/export" => {
            request("GET", "/api/v1/admin/audit/export?format=jsonl", t, None)
        }
        "POST /api/v1/admin/audit/evidence-packs" => {
            let now = chrono::Utc::now();
            request(
                "POST",
                "/api/v1/admin/audit/evidence-packs",
                t,
                Some(json!({
                    "from": (now - chrono::Duration::minutes(5)).to_rfc3339(),
                    "to": now.to_rfc3339(),
                })),
            )
        }
        // ── data protection ─────────────────────────────────────────────────
        "POST /api/v1/admin/dsr/requests/{id}/fulfill-erasure" => {
            let subject = uniq("dsr-subject");
            entity_record(fx, &subject).await;
            let dsr = admin(
                fx,
                "POST",
                "/api/v1/admin/dsr/requests",
                Some(json!({"subject_reference": subject, "request_type": "erasure"})),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/dsr/requests/{}/fulfill-erasure", id_of(&dsr)),
                t,
                Some(json!({"scopes": [
                    {"entity_logicalname": fx.entity, "match_attribute": "title"},
                ]})),
            )
        }
        "POST /api/v1/admin/dsr/requests/{id}/restrict" => {
            let subject = uniq("dsr-restrict");
            entity_record(fx, &subject).await;
            let dsr = admin(
                fx,
                "POST",
                "/api/v1/admin/dsr/requests",
                Some(json!({"subject_reference": subject, "request_type": "restriction"})),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/dsr/requests/{}/restrict", id_of(&dsr)),
                t,
                Some(json!({"scopes": [
                    {"entity_logicalname": fx.entity, "match_attribute": "title"},
                ]})),
            )
        }
        "POST /api/v1/admin/dsr/requests/{id}/lift" => {
            // R1-T1: restrict a subject's record, then lift it.
            let subject = uniq("dsr-lift");
            entity_record(fx, &subject).await;
            let dsr = admin(
                fx,
                "POST",
                "/api/v1/admin/dsr/requests",
                Some(json!({"subject_reference": subject, "request_type": "restriction"})),
            )
            .await;
            admin(
                fx,
                "POST",
                &format!("/api/v1/admin/dsr/requests/{}/restrict", id_of(&dsr)),
                Some(json!({"scopes": [
                    {"entity_logicalname": fx.entity, "match_attribute": "title"},
                ]})),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/dsr/requests/{}/lift", id_of(&dsr)),
                t,
                None,
            )
        }
        "POST /api/v1/admin/dsr/requests/{id}/rectify" => {
            let dsr = admin(
                fx,
                "POST",
                "/api/v1/admin/dsr/requests",
                Some(json!({"subject_reference": uniq("dsr-rectify"), "request_type": "rectification"})),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/dsr/requests/{}/rectify", id_of(&dsr)),
                t,
                Some(json!({"outcome": "fulfilled", "resolution": "Phone number corrected"})),
            )
        }
        "POST /api/v1/admin/security/erasure/{logicalname}/{record_id}" => {
            // A fresh record: erasure destroys the record's audit key.
            let record = entity_record(fx, &uniq("erased")).await;
            request(
                "POST",
                &format!("{S}/erasure/{}/{record}", fx.entity),
                t,
                None,
            )
        }
        "POST /api/v1/admin/security/rewrap/{domain}" => {
            request("POST", &format!("{S}/rewrap/mfa"), t, None)
        }
        // ── stored queries, views, sidebar ──────────────────────────────────
        "POST /api/v1/admin/queries" => request(
            "POST",
            "/api/v1/admin/queries",
            t,
            Some(json!({"sql_query": "SELECT 1 AS id"})),
        ),
        "PATCH /api/v1/admin/queries/{id}" => {
            let id = stored_query(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/admin/queries/{id}"),
                t,
                Some(json!({"sql_query": "SELECT 2 AS id"})),
            )
        }
        "DELETE /api/v1/admin/queries/{id}" => {
            let id = stored_query(fx).await;
            request("DELETE", &format!("/api/v1/admin/queries/{id}"), t, None)
        }
        // ── Hijri sighting correction (AG1-T3) ──────────────────────────────
        // 1447: Safar has 29 days and Rabi al-Awwal 30, so Rabi al-Awwal may
        // start a day after its published 2025-08-24. Idempotent on reruns.
        "PUT /api/v1/admin/hijri-months/{year}/{month}" => request(
            "PUT",
            "/api/v1/admin/hijri-months/1447/3",
            t,
            Some(json!({"gregorian_start": "2025-08-25", "reason": "audit emission"})),
        ),
        // ── brand themes (B13-T4) ───────────────────────────────────────────
        "POST /api/v1/admin/themes" => request(
            "POST",
            "/api/v1/admin/themes",
            t,
            Some(json!({"scope_kind": "portal", "scope_ref": uniq("portal"), "tokens": {}})),
        ),
        "PATCH /api/v1/admin/themes/{id}" => {
            let created = admin(
                fx,
                "POST",
                "/api/v1/admin/themes",
                Some(json!({"scope_kind": "portal", "scope_ref": uniq("portal"), "tokens": {}})),
            )
            .await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/themes/{}", id_of(&created)),
                    t,
                    Some(json!({"tokens": {"primary": "#111111"}})),
                ),
                created["row_version"].as_i64().expect("row_version"),
            )
        }
        "POST /api/v1/admin/themes/{id}/publish" => {
            let created = admin(
                fx,
                "POST",
                "/api/v1/admin/themes",
                Some(json!({"scope_kind": "portal", "scope_ref": uniq("portal"), "tokens": {}})),
            )
            .await;
            with_if_match(
                request(
                    "POST",
                    &format!("/api/v1/admin/themes/{}/publish", id_of(&created)),
                    t,
                    None,
                ),
                created["row_version"].as_i64().expect("row_version"),
            )
        }
        "POST /api/v1/admin/themes/rollback" => {
            let scope_ref = uniq("portal");
            let created = admin(
                fx,
                "POST",
                "/api/v1/admin/themes",
                Some(json!({"scope_kind": "portal", "scope_ref": scope_ref, "tokens": {}})),
            )
            .await;
            call(
                fx,
                with_if_match(
                    request(
                        "POST",
                        &format!("/api/v1/admin/themes/{}/publish", id_of(&created)),
                        t,
                        None,
                    ),
                    created["row_version"].as_i64().expect("row_version"),
                ),
            )
            .await;
            request(
                "POST",
                "/api/v1/admin/themes/rollback",
                t,
                Some(json!({"scope_kind": "portal", "scope_ref": scope_ref, "version": 1})),
            )
        }
        // ── recycle bin rules (A18-T7) ──────────────────────────────────────
        "PUT /api/v1/admin/bin-settings/{entity}" => request(
            "PUT",
            &format!("/api/v1/admin/bin-settings/{}", fx.entity),
            t,
            Some(json!({"require_reason": false, "retention_days": 30})),
        ),
        // ── tag groups (B4-T2) ──────────────────────────────────────────────
        "POST /api/v1/admin/tag-groups" => request(
            "POST",
            "/api/v1/admin/tag-groups",
            t,
            Some(json!({"name": uniq("tags"), "create_policy": "anyone"})),
        ),
        // ── team favourites (B9-T2) ─────────────────────────────────────────
        "POST /api/v1/teams/{team_id}/favourites/lists" => {
            let team_id = team(fx).await;
            request(
                "POST",
                &format!("/api/v1/teams/{team_id}/favourites/lists"),
                t,
                Some(
                    json!({"name": uniq("team-list"), "items": [{"kind": "page", "ref": "/dashboard"}]}),
                ),
            )
        }
        "PUT /api/v1/teams/{team_id}/favourites/lists/{id}" => {
            let team_id = team(fx).await;
            let created = admin(
                fx,
                "POST",
                &format!("/api/v1/teams/{team_id}/favourites/lists"),
                Some(json!({"name": uniq("team-list")})),
            )
            .await;
            request(
                "PUT",
                &format!(
                    "/api/v1/teams/{team_id}/favourites/lists/{}",
                    id_of(&created)
                ),
                t,
                Some(
                    json!({"name": uniq("team-list"), "items": [{"kind": "page", "ref": "/x", "pinned": true}]}),
                ),
            )
        }
        "DELETE /api/v1/teams/{team_id}/favourites/lists/{id}" => {
            let team_id = team(fx).await;
            let created = admin(
                fx,
                "POST",
                &format!("/api/v1/teams/{team_id}/favourites/lists"),
                Some(json!({"name": uniq("team-list")})),
            )
            .await;
            request(
                "DELETE",
                &format!(
                    "/api/v1/teams/{team_id}/favourites/lists/{}",
                    id_of(&created)
                ),
                t,
                None,
            )
        }
        "POST /api/v1/admin/views" => {
            let query_id = stored_query(fx).await;
            request(
                "POST",
                "/api/v1/admin/views",
                t,
                Some(view_body(fx, query_id)),
            )
        }
        "PATCH /api/v1/admin/views/{id}" => {
            let query_id = stored_query(fx).await;
            let created = admin(
                fx,
                "POST",
                "/api/v1/admin/views",
                Some(view_body(fx, query_id)),
            )
            .await;
            request(
                "PATCH",
                &format!("/api/v1/admin/views/{}", id_of(&created)),
                t,
                Some(view_body(fx, query_id)),
            )
        }
        "DELETE /api/v1/admin/views/{id}" => {
            let id = system_view(fx).await;
            request("DELETE", &format!("/api/v1/admin/views/{id}"), t, None)
        }
        "POST /api/v1/views/{id}/share" => {
            let query_id = stored_query(fx).await;
            let personal = admin(
                fx,
                "POST",
                "/api/v1/views",
                Some(json!({
                    "name": uniq("personal-view"),
                    "entity": fx.entity,
                    "sql_query_ref": query_id,
                    "table_definition": [],
                })),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/views/{}/share", id_of(&personal)),
                t,
                None,
            )
        }
        "POST /api/v1/sidebar/admin" => request(
            "POST",
            "/api/v1/sidebar/admin",
            t,
            Some(json!({"name": uniq("sidebar"), "display_order": 900})),
        ),
        "PATCH /api/v1/sidebar/admin/{id}" => {
            let (id, row_version) = sidebar_item(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/sidebar/admin/{id}"),
                t,
                Some(json!({
                    "name": uniq("sidebar-renamed"),
                    "display_order": 901,
                    "row_version": row_version,
                })),
            )
        }
        "DELETE /api/v1/sidebar/admin/{id}" => {
            let (id, row_version) = sidebar_item(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/sidebar/admin/{id}"),
                t,
                Some(json!({"row_version": row_version})),
            )
        }
        // ── v2 metadata model (Y1) ──────────────────────────────────────────
        "POST /api/v1/admin/model/{kind}/{id}/commands" => {
            let id = Uuid::now_v7();
            request(
                "POST",
                &format!("/api/v1/admin/model/agent/{id}/commands"),
                t,
                Some(json!({
                    "base_hash": "",
                    "name": format!("emission draft {id}"),
                    "commands": agent_commands(Uuid::now_v7(), Uuid::now_v7()),
                })),
            )
        }
        "POST /api/v1/admin/model/{kind}/{id}/publish" => {
            let id = Uuid::now_v7();
            call(
                fx,
                request(
                    "POST",
                    &format!("/api/v1/admin/model/agent/{id}/commands"),
                    t,
                    Some(json!({
                        "base_hash": "",
                        "name": format!("emission publish {id}"),
                        "commands": agent_commands(Uuid::now_v7(), Uuid::now_v7()),
                    })),
                ),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/model/agent/{id}/publish"),
                t,
                None,
            )
        }
        // ── outside MCP servers (N13-T1) ────────────────────────────────────
        "POST /api/v1/admin/mcp-servers" => request(
            "POST",
            "/api/v1/admin/mcp-servers",
            t,
            Some(
                json!({"name": format!("emission {}", Uuid::now_v7()), "url": "http://127.0.0.1:9/mcp"}),
            ),
        ),
        "PUT /api/v1/admin/mcp-servers/{id}/tools/{tool}" => {
            let created = call(
                fx,
                request(
                    "POST",
                    "/api/v1/admin/mcp-servers",
                    t,
                    Some(json!({"name": format!("emission tools {}", Uuid::now_v7()), "url": "http://127.0.0.1:9/mcp"})),
                ),
            )
            .await;
            let id = created["id"].as_str().unwrap_or_default().to_owned();
            sqlx::query(
                "INSERT INTO mcp_server_tool (server_ref, name) VALUES ($1::uuid, 'lookup')",
            )
            .bind(&id)
            .execute(&fx.base.db)
            .await
            .expect("insert an MCP tool");
            request(
                "PUT",
                &format!("/api/v1/admin/mcp-servers/{id}/tools/lookup"),
                t,
                Some(json!({"risk": "read", "enabled": true})),
            )
        }
        // ── v2 agents (V2-D487, N23, N30, N31) ──────────────────────────────
        "POST /api/v1/model/agents/{agent}/sessions" => {
            let agent = agent_object(fx).await;
            request(
                "POST",
                &format!("/api/v1/model/agents/{agent}/sessions"),
                t,
                Some(json!({"risk_ceiling": "read"})),
            )
        }
        "POST /api/v1/admin/ai/eval-suites/{suite}/runs" => {
            // The cases run in the background and fail without an inference
            // endpoint; the run row and its event are written first.
            let suite = eval_suite(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/ai/eval-suites/{suite}/runs"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/ai/eval-suites/{suite}/cases/from-message" => {
            let suite = eval_suite(fx).await;
            let message = answered_message(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/ai/eval-suites/{suite}/cases/from-message"),
                t,
                Some(json!({"message_id": message, "expect": {"text_matches": "balance"}})),
            )
        }
        "POST /api/v1/admin/ai/write-policies" => request(
            "POST",
            "/api/v1/admin/ai/write-policies",
            t,
            Some(json!({"action_id": "record.update", "entity": fx.entity, "reason": "emission"})),
        ),
        "DELETE /api/v1/admin/ai/write-policies/{id}" => {
            let created = call(
                fx,
                request(
                    "POST",
                    "/api/v1/admin/ai/write-policies",
                    t,
                    Some(json!({"action_id": "record.update", "entity": fx.entity})),
                ),
            )
            .await;
            let id = created["id"].as_str().unwrap_or_default().to_owned();
            request(
                "DELETE",
                &format!("/api/v1/admin/ai/write-policies/{id}"),
                t,
                None,
            )
        }
        "PUT /api/v1/admin/ai/switches/{kind}/{key}" => request(
            // A channel no other driver uses, so switching it off changes
            // nothing for the routes driven after it.
            "PUT",
            "/api/v1/admin/ai/switches/channel/emission",
            t,
            Some(json!({"enabled": false, "reason": "emission"})),
        ),
        // ── AI sessions ─────────────────────────────────────────────────────
        "POST /api/v1/agents/{id}/sessions" => {
            let definition = agent_definition(fx).await;
            request(
                "POST",
                &format!("/api/v1/agents/{definition}/sessions"),
                t,
                Some(json!({"risk_ceiling": "read"})),
            )
        }
        // ── C4 chat API ─────────────────────────────────────────────────────
        "POST /api/v1/ai/conversations" => {
            let definition = agent_definition(fx).await;
            request(
                "POST",
                "/api/v1/ai/conversations",
                t,
                Some(json!({"agent_definition_id": definition, "risk_ceiling": "read"})),
            )
        }
        "POST /api/v1/ai/conversations/{id}/messages" => {
            // No inference endpoint is configured here, so the turn itself
            // answers `503 capability_unavailable` — but only after the human's
            // message and its mandatory event committed, which is the first
            // write of every turn and what this mapping audits.
            let conversation = chat_conversation(fx).await;
            return Some((
                request(
                    "POST",
                    &format!("/api/v1/ai/conversations/{conversation}/messages"),
                    t,
                    Some(json!({"text": "hello"})),
                ),
                Some(StatusCode::SERVICE_UNAVAILABLE),
            ));
        }
        "POST /api/v1/ai/conversations/{id}/tool-calls/{tid}/confirm" => {
            let (conversation, tid, hash) = chat_proposal(fx).await;
            request(
                "POST",
                &format!("/api/v1/ai/conversations/{conversation}/tool-calls/{tid}/confirm"),
                t,
                Some(json!({"arguments_hash": hash})),
            )
        }
        "DELETE /api/v1/ai/conversations/{id}/tool-calls/{tid}" => {
            let (conversation, tid, _) = chat_proposal(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/ai/conversations/{conversation}/tool-calls/{tid}"),
                t,
                None,
            )
        }
        "PUT /api/v1/ai/conversations/{id}/messages/{message_id}/feedback" => {
            // C10-B — a vote on a turn's answer (an assistant message carrying
            // a terminal state).
            let conversation = chat_conversation(fx).await;
            let answer = attome_ai::conversation::append(
                &fx.base.db,
                attome_ai::conversation::NewMessage {
                    conversation_id: conversation,
                    role: attome_ai::conversation::Role::Assistant,
                    content: "an answer".into(),
                    turn_id: Uuid::now_v7(),
                    terminal_state: Some(attome_ai::conversation::TerminalState::Completed),
                    model_id: None,
                    prompt_version: None,
                    input_tokens: None,
                    output_tokens: None,
                },
            )
            .await
            .expect("append an answer")
            .id;
            request(
                "PUT",
                &format!("/api/v1/ai/conversations/{conversation}/messages/{answer}/feedback"),
                t,
                Some(json!({"vote": "up"})),
            )
        }
        "POST /api/v1/ai/conversations/{id}/turns/{turn_id}/cancel" => {
            // C11 B4 — Stop on a turn that has begun and not ended: its user
            // message, with no answer yet. The recorded Stop is what is audited.
            let conversation = chat_conversation(fx).await;
            let turn = Uuid::now_v7();
            attome_ai::conversation::append(
                &fx.base.db,
                attome_ai::conversation::NewMessage {
                    conversation_id: conversation,
                    role: attome_ai::conversation::Role::User,
                    content: "a long job".into(),
                    turn_id: turn,
                    terminal_state: None,
                    model_id: None,
                    prompt_version: None,
                    input_tokens: None,
                    output_tokens: None,
                },
            )
            .await
            .expect("append a running turn");
            request(
                "POST",
                &format!("/api/v1/ai/conversations/{conversation}/turns/{turn}/cancel"),
                t,
                Some(json!({})),
            )
        }
        "PUT /api/v1/admin/ai/runtime-switch/{surface}" => {
            // C11 B5 — turning a surface ON leaves every other suite's AI
            // behaviour as the configuration has it: the switch only narrows.
            request(
                "PUT",
                "/api/v1/admin/ai/runtime-switch/workflow_nodes",
                t,
                Some(json!({"enabled": true, "reason": "audit emission"})),
            )
        }
        "DELETE /api/v1/ai/conversations/{id}" => {
            let conversation = chat_conversation(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/ai/conversations/{conversation}"),
                t,
                None,
            )
        }
        "POST /api/v1/mcp" => request(
            "POST",
            "/api/v1/mcp",
            t,
            Some(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})),
        ),
        // ── licence ─────────────────────────────────────────────────────────
        "PUT /api/v1/admin/license/modules" => request(
            "PUT",
            "/api/v1/admin/license/modules",
            t,
            Some(json!({"enabled": false, "modules": []})),
        ),
        "POST /api/v1/admin/content/pages" => {
            let space_id = content_space(fx).await;
            request(
                "POST",
                "/api/v1/admin/content/pages",
                t,
                Some(json!({
                    "content_space_id": space_id,
                    "title": uniq("page"),
                    "url_path": format!("/{}", uniq("path")),
                })),
            )
        }
        "PATCH /api/v1/admin/content/pages/{id}" => {
            let (id, row_version) = content_page(fx).await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/content/pages/{id}"),
                    t,
                    Some(json!({"title": uniq("page-renamed")})),
                ),
                row_version,
            )
        }
        "DELETE /api/v1/admin/content/pages/{id}" => {
            let (id, _) = content_page(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/content/pages/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/content/pages/{id}/move" => {
            let (id, _) = content_page(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/move"),
                t,
                Some(json!({"parent_page_id": null})),
            )
        }
        "POST /api/v1/admin/content/pages/{id}/publish" => {
            let (id, _) = content_page(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/publish"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/content/pages/{id}/versions/{number}/restore" => {
            // K5-T1: publish once so version 1 exists, then restore it.
            let (id, _) = content_page(fx).await;
            admin(
                fx,
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/publish"),
                None,
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/versions/1/restore"),
                t,
                None,
            )
        }
        "PUT /api/v1/admin/content/pages/{id}/audience" => {
            let (id, _) = content_page(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/content/pages/{id}/audience"),
                t,
                Some(json!({"audience": "internal"})),
            )
        }
        "POST /api/v1/admin/content/pages/{id}/preview-link" => {
            let (id, _) = content_page(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/preview-link"),
                t,
                Some(json!({"minutes": 30})),
            )
        }
        "POST /api/v1/admin/content/pages/{id}/translations" => {
            let (id, _) = content_page(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/translations"),
                t,
                Some(
                    json!({"language": "ar", "title": "Arabic", "url_path": format!("/{}", uniq("ar"))}),
                ),
            )
        }
        "POST /api/v1/admin/content/pages/{id}/translation/current" => {
            // K5-T4: translate a page, then mark the translation current.
            let (id, _) = content_page(fx).await;
            let created = admin(
                fx,
                "POST",
                &format!("/api/v1/admin/content/pages/{id}/translations"),
                Some(json!({"language": "ar", "title": "Arabic", "url_path": format!("/{}", uniq("ar"))})),
            )
            .await;
            let translation = id_of(&created);
            request(
                "POST",
                &format!("/api/v1/admin/content/pages/{translation}/translation/current"),
                t,
                None,
            )
        }
        "PUT /api/v1/admin/content/pages/{id}/article" => {
            // G11-T1: no knowledge source keeps it an ordinary page; the
            // settings write and its event happen either way.
            let (id, _) = content_page(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/content/pages/{id}/article"),
                t,
                Some(json!({"knowledge_source_id": null, "category": "Accounts"})),
            )
        }
        "PUT /api/v1/admin/content/pages/{id}/schedule" => {
            let (id, row_version) = content_page(fx).await;
            with_if_match(
                request(
                    "PUT",
                    &format!("/api/v1/admin/content/pages/{id}/schedule"),
                    t,
                    Some(json!({"publish_at": null, "unpublish_at": null})),
                ),
                row_version,
            )
        }
        "PUT /api/v1/admin/content/pages/{id}/related" => {
            let (id, _) = content_page(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/content/pages/{id}/related"),
                t,
                Some(json!({"related_page_ids": []})),
            )
        }
        "PATCH /api/v1/admin/content/pages/{id}/review-by" => {
            let (id, row_version) = content_page(fx).await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/content/pages/{id}/review-by"),
                    t,
                    Some(json!({"review_by": null})),
                ),
                row_version,
            )
        }
        "POST /api/v1/admin/content/spaces" => request(
            "POST",
            "/api/v1/admin/content/spaces",
            t,
            Some(json!({"name": uniq("content-space")})),
        ),
        "PATCH /api/v1/admin/content/spaces/{id}" => {
            let id = content_space(fx).await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/content/spaces/{id}"),
                    t,
                    Some(json!({"name": uniq("content-space-renamed")})),
                ),
                0, // migration 0135: row_version DEFAULT 0, and this space was just created
            )
        }
        "DELETE /api/v1/admin/content/spaces/{id}" => {
            let id = content_space(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/content/spaces/{id}"),
                t,
                None,
            )
        }
        "PUT /api/v1/admin/content/spaces/{id}/templates" => {
            let id = content_space(fx).await;
            let template_id = content_template(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/content/spaces/{id}/templates"),
                t,
                Some(json!({"template_ids": [template_id]})),
            )
        }
        "POST /api/v1/admin/content/templates" => request(
            "POST",
            "/api/v1/admin/content/templates",
            t,
            Some(json!({"name": uniq("content-template"), "blocks": []})),
        ),
        "PATCH /api/v1/admin/content/templates/{id}" => {
            let id = content_template(fx).await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/content/templates/{id}"),
                    t,
                    Some(json!({"name": uniq("content-template-renamed")})),
                ),
                0, // migration 0135: row_version DEFAULT 0, and this template was just created
            )
        }
        "DELETE /api/v1/admin/content/templates/{id}" => {
            let id = content_template(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/content/templates/{id}"),
                t,
                None,
            )
        }
        // ── AI sessions ─────────────────────────────────────────────────────
        "POST /api/v1/admin/data/match-rules" => request(
            "POST",
            "/api/v1/admin/data/match-rules",
            t,
            Some(json!({
                "name": uniq("match-rule"),
                "entity": fx.entity,
                "fields": [{"field": "title", "comparator": "exact", "weight": 1.0}],
                "threshold": 0.9,
                "is_active": true,
                "auto_merge": false,
            })),
        ),
        "PUT /api/v1/admin/data/match-rules/{id}" => {
            let (id, row_version) = match_rule(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/data/match-rules/{id}"),
                t,
                Some(json!({"is_active": false, "row_version": row_version})),
            )
        }
        "POST /api/v1/admin/data/match-rules/{id}/scan" => {
            let (id, _) = match_rule(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/data/match-rules/{id}/scan"),
                t,
                None,
            )
        }
        "DELETE /api/v1/admin/data/match-rules/{id}" => {
            let (id, _) = match_rule(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/data/match-rules/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/data/survivorship-rules" => request(
            "POST",
            "/api/v1/admin/data/survivorship-rules",
            t,
            Some(json!({
                "entity": fx.entity,
                "field": "title",
                "strategy": "most_recent",
            })),
        ),
        "DELETE /api/v1/admin/data/survivorship-rules/{id}" => {
            let id = survivorship_rule(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/data/survivorship-rules/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/data/mappings" => request(
            "POST",
            "/api/v1/admin/data/mappings",
            t,
            Some(json!({
                "name": uniq("mapping"),
                "target_entity": fx.entity,
                "source_kind": "csv",
                "fields": [{"source": "Title", "target": "title"}],
            })),
        ),
        "PUT /api/v1/admin/data/mappings/{id}" => {
            let id = data_mapping(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/data/mappings/{id}"),
                t,
                Some(json!({"name": uniq("mapping-renamed")})),
            )
        }
        "DELETE /api/v1/admin/data/mappings/{id}" => {
            let id = data_mapping(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/data/mappings/{id}"),
                t,
                None,
            )
        }
        // ── state models (audit-10-10 Phase 3.7 part G) ─────────────────────
        "POST /api/v1/admin/state-models" => {
            let entity = state_model_entity(fx).await;
            request(
                "POST",
                "/api/v1/admin/state-models",
                t,
                Some(json!({
                    "entity_logicalname": entity, "name": "Audit Emission Lifecycle",
                    "state_field": "status", "initial_state": "new", "is_active": true,
                })),
            )
        }
        "PATCH /api/v1/admin/state-models/{id}" => {
            let (model, _) = state_model_with_transition(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/admin/state-models/{}", id_of(&model)),
                t,
                Some(json!({
                    "name": "Renamed Lifecycle", "state_field": "status", "initial_state": "new",
                    "is_active": true, "row_version": model["row_version"],
                })),
            )
        }
        "DELETE /api/v1/admin/state-models/{id}" => {
            let (model, _) = state_model_with_transition(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/state-models/{}", id_of(&model)),
                t,
                None,
            )
        }
        "POST /api/v1/admin/state-models/{id}/transitions" => {
            let (model, _) = state_model_with_transition(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/state-models/{}/transitions", id_of(&model)),
                t,
                Some(json!({"from_state": "active", "to_state": "done", "name": "Finish"})),
            )
        }
        "PATCH /api/v1/admin/state-models/{id}/transitions/{transition_id}" => {
            let (model, transition) = state_model_with_transition(fx).await;
            request(
                "PATCH",
                &format!(
                    "/api/v1/admin/state-models/{}/transitions/{}",
                    id_of(&model),
                    id_of(&transition)
                ),
                t,
                Some(json!({"name": "Renamed Start", "row_version": transition["row_version"]})),
            )
        }
        "DELETE /api/v1/admin/state-models/{id}/transitions/{transition_id}" => {
            let (model, transition) = state_model_with_transition(fx).await;
            request(
                "DELETE",
                &format!(
                    "/api/v1/admin/state-models/{}/transitions/{}",
                    id_of(&model),
                    id_of(&transition)
                ),
                t,
                None,
            )
        }
        "POST /api/v1/{entity}/{id}/transition/cancel" => {
            // M07 Phase F (D-770): a record parked in `active` by a
            // `new -> done` transition that requires one approval, cancelled
            // by its requester (the admin), which writes Security/Cancelled.
            let entity = state_model_entity(fx).await;
            let (approver, _) = seed_user(&fx.base, "transition-approver").await;
            let model = admin(
                fx,
                "POST",
                "/api/v1/admin/state-models",
                Some(json!({
                    "entity_logicalname": entity, "name": "Audit Emission Approval",
                    "state_field": "status", "initial_state": "new", "is_active": true,
                })),
            )
            .await;
            admin(
                fx,
                "POST",
                &format!("/api/v1/admin/state-models/{}/transitions", id_of(&model)),
                Some(json!({
                    "from_state": "new", "to_state": "done", "name": "Finish",
                    "approval_plan": {"steps": [{
                        "mode": "any", "approvers": [format!("user:{approver}")],
                        "sla_minutes": null,
                    }]},
                    "pending_state": "active",
                })),
            )
            .await;
            let record = admin(fx, "POST", &format!("/api/v1/{entity}"), Some(json!({}))).await;
            let record_id = id_of(&record);
            admin(
                fx,
                "POST",
                &format!("/api/v1/{entity}/{record_id}/transition"),
                Some(json!({"to_state": "done"})),
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/{entity}/{record_id}/transition/cancel"),
                t,
                Some(json!({})),
            )
        }
        // ── workflow (audit-10-10 Phase 3.7 part G) ─────────────────────────
        "POST /api/v1/workflow/definitions" => {
            let logicalname = format!("audit_emit_wf_{}", Uuid::now_v7().simple());
            request(
                "POST",
                "/api/v1/workflow/definitions",
                t,
                Some(json!({"logicalname": logicalname, "name": "Audit Emission Workflow"})),
            )
        }
        "PATCH /api/v1/workflow/definitions/{id}" => {
            let def = workflow_definition(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/workflow/definitions/{}", id_of(&def)),
                t,
                Some(json!({"name": "Renamed Workflow", "row_version": def["row_version"]})),
            )
        }
        "DELETE /api/v1/workflow/definitions/{id}" => {
            let def = workflow_definition(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/workflow/definitions/{}", id_of(&def)),
                t,
                None,
            )
        }
        "POST /api/v1/workflow/definitions/{id}/versions" => {
            let def = workflow_definition(fx).await;
            request(
                "POST",
                &format!("/api/v1/workflow/definitions/{}/versions", id_of(&def)),
                t,
                Some(json!({})),
            )
        }
        "PATCH /api/v1/workflow/definitions/{id}/versions/{version_id}" => {
            let (def, version) = workflow_definition_with_version(fx).await;
            request(
                "PATCH",
                &format!(
                    "/api/v1/workflow/definitions/{}/versions/{}",
                    id_of(&def),
                    id_of(&version)
                ),
                t,
                Some(json!({"graph": trigger_only_graph(), "row_version": version["row_version"]})),
            )
        }
        "POST /api/v1/workflow/definitions/{id}/versions/{version_id}/publish" => {
            let (def, version) = workflow_definition_with_version(fx).await;
            request(
                "POST",
                &format!(
                    "/api/v1/workflow/definitions/{}/versions/{}/publish",
                    id_of(&def),
                    id_of(&version)
                ),
                t,
                None,
            )
        }
        "DELETE /api/v1/admin/rate-limits/bans/{bucket}" => {
            let bucket = format!("ip:198.51.100.{}", Uuid::now_v7().as_u128() % 250);
            fx.base
                .redis_coordination
                .set(
                    attome_server::middleware::rate_limit::ban_key(&bucket),
                    "auth",
                    Some(std::time::Duration::from_secs(600)),
                )
                .await
                .expect("seed ban");
            request(
                "DELETE",
                &format!("/api/v1/admin/rate-limits/bans/{bucket}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/change-feed/consumers/{name}/rewind" => {
            // A consumer exists once it first reads; seed one, and an event
            // to rewind to.
            let consumer = uniq("rewind-consumer");
            sqlx::query("INSERT INTO change_consumer_cursor (consumer) VALUES ($1)")
                .bind(&consumer)
                .execute(&fx.base.db)
                .await
                .expect("seed consumer");
            sqlx::query(
                "INSERT INTO entity_change_event (entity_logicalname, record_id, operation) \
                 VALUES ('rewind_probe', $1, 'create')",
            )
            .bind(Uuid::now_v7())
            .execute(&fx.base.db)
            .await
            .expect("seed event");
            let seq: i64 = sqlx::query_scalar("SELECT max(seq) FROM entity_change_event")
                .fetch_one(&fx.base.db)
                .await
                .expect("read seq");
            request(
                "POST",
                &format!("/api/v1/admin/change-feed/consumers/{consumer}/rewind"),
                t,
                Some(json!({"to_seq": seq})),
            )
        }
        "POST /api/v1/workflow/instances" => {
            let logicalname = published_workflow(fx).await;
            request(
                "POST",
                "/api/v1/workflow/instances",
                t,
                Some(json!({"definition_logicalname": logicalname})),
            )
        }
        "POST /api/v1/workflow/instances/{id}/cancel" => {
            let logicalname = published_workflow(fx).await;
            let instance = admin(
                fx,
                "POST",
                "/api/v1/workflow/instances",
                Some(json!({"definition_logicalname": logicalname})),
            )
            .await;
            let instance_id = id_of(&instance);
            request(
                "POST",
                &format!("/api/v1/workflow/instances/{instance_id}/cancel"),
                t,
                Some(json!({"row_version": 0})),
            )
        }
        // ── Predict (Phase 3.7 part H) ───────────────────────────────────────
        "POST /api/v1/admin/predict/models" => request(
            "POST",
            "/api/v1/admin/predict/models",
            t,
            Some(json!({
                "name": uniq("predict-model"),
                "target": "sla_breach",
                "entity": "service_ticket",
            })),
        ),
        "POST /api/v1/admin/predict/models/{id}/train" => {
            let id = idle_predict_model(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/predict/models/{id}/train"),
                t,
                None,
            )
        }
        "DELETE /api/v1/admin/predict/models/{id}" => {
            let id = idle_predict_model(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/predict/models/{id}"),
                t,
                None,
            )
        }
        // ── Relationships (Phase 3.7 part H) ─────────────────────────────────
        "POST /api/v1/admin/relationships" => {
            let entity_b = second_entity(fx).await;
            request(
                "POST",
                "/api/v1/admin/relationships",
                t,
                Some(json!({
                    "name": format!("rel_{}", Uuid::now_v7().simple()),
                    "entity_a": fx.entity,
                    "entity_b": entity_b,
                    "role_a": "parent",
                    "role_b": "child",
                })),
            )
        }
        "PATCH /api/v1/admin/relationships/{id}" => {
            let rel = relationship(fx).await;
            request(
                "PATCH",
                &format!("/api/v1/admin/relationships/{}", id_of(&rel)),
                t,
                Some(json!({"role_a": "updated-role"})),
            )
        }
        "DELETE /api/v1/admin/relationships/{id}" => {
            let rel = relationship(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/relationships/{}", id_of(&rel)),
                t,
                None,
            )
        }
        // ── Retention rules (R3-T1) ──────────────────────────────────────────
        "POST /api/v1/admin/retention/rules" => request(
            "POST",
            "/api/v1/admin/retention/rules",
            t,
            Some(
                json!({"name": uniq("rule"), "entity": fx.entity, "period_days": 365, "action": "review"}),
            ),
        ),
        "PUT /api/v1/admin/retention/rules/{id}" => {
            let id = retention_rule(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/retention/rules/{id}"),
                t,
                Some(
                    json!({"name": uniq("rule"), "entity": fx.entity, "period_days": 730, "action": "review"}),
                ),
            )
        }
        "DELETE /api/v1/admin/retention/rules/{id}" => {
            let id = retention_rule(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/retention/rules/{id}"),
                t,
                None,
            )
        }
        // ── Retention (Phase 3.7 part H) ─────────────────────────────────────
        "POST /api/v1/admin/retention/actions/{id}/reject" => {
            let id = retention_action(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/retention/actions/{id}/reject"),
                t,
                None,
            )
        }
        // ── Process case-defs (Phase 3.7 part H) ─────────────────────────────
        "POST /api/v1/process/case-defs" => request(
            "POST",
            "/api/v1/process/case-defs",
            t,
            Some(json!({"name": uniq("case-def"), "source": format!("entity:{}", fx.entity)})),
        ),
        "PATCH /api/v1/process/case-defs/{id}" => {
            let cd = case_def(fx).await;
            let row_version = cd["row_version"].as_i64().unwrap_or(0);
            request(
                "PATCH",
                &format!("/api/v1/process/case-defs/{}", id_of(&cd)),
                t,
                Some(json!({
                    "name": uniq("case-def-renamed"),
                    "is_active": true,
                    "row_version": row_version,
                })),
            )
        }
        "DELETE /api/v1/process/case-defs/{id}" => {
            let cd = case_def(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/process/case-defs/{}", id_of(&cd)),
                t,
                None,
            )
        }
        // ── apps, email, events, governance (Phase 3.7 part F) ──────────────
        "POST /api/v1/admin/apps" => request(
            "POST",
            "/api/v1/admin/apps",
            t,
            Some(json!({"name": uniq("app")})),
        ),
        "PATCH /api/v1/admin/apps/{id}" => {
            let app = app_fixture(fx).await;
            let id = id_of(&app);
            request(
                "PATCH",
                &format!("/api/v1/admin/apps/{id}"),
                t,
                Some(json!({"name": uniq("renamed-app")})),
            )
        }
        "DELETE /api/v1/admin/apps/{id}" => {
            let app = app_fixture(fx).await;
            let id = id_of(&app);
            request("DELETE", &format!("/api/v1/admin/apps/{id}"), t, None)
        }
        "POST /api/v1/admin/email/deliveries/{id}/resend" => {
            let id = email_delivery_fixture(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/email/deliveries/{id}/resend"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/email/suppressions" => request(
            "POST",
            "/api/v1/admin/email/suppressions",
            t,
            Some(json!({"email": format!("{}@example.com", uniq("suppress"))})),
        ),
        "DELETE /api/v1/admin/email/suppressions/{id}" => {
            let (_, id) = email_suppression_fixture(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/email/suppressions/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/events/subscriptions" => request(
            "POST",
            "/api/v1/admin/events/subscriptions",
            t,
            Some(json!({
                "name": uniq("sub"),
                "kind": "webhook",
                "target_url": SAFE_WEBHOOK_URL,
                "owner_ref": fx.admin_id,
            })),
        ),
        "PATCH /api/v1/admin/events/subscriptions/{id}" => {
            let sub = event_subscription_fixture(fx).await;
            let id = id_of(&sub);
            request(
                "PATCH",
                &format!("/api/v1/admin/events/subscriptions/{id}"),
                t,
                Some(json!({"is_active": false, "row_version": 0})),
            )
        }
        "DELETE /api/v1/admin/events/subscriptions/{id}" => {
            let sub = event_subscription_fixture(fx).await;
            let id = id_of(&sub);
            request(
                "DELETE",
                &format!("/api/v1/admin/events/subscriptions/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/events/subscriptions/{id}/secret/rotate" => {
            let sub = event_subscription_fixture(fx).await;
            let id = id_of(&sub);
            request(
                "POST",
                &format!("/api/v1/admin/events/subscriptions/{id}/secret/rotate"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/governance/domains" => request(
            "POST",
            "/api/v1/admin/governance/domains",
            t,
            Some(json!({"name": uniq("domain")})),
        ),
        "PATCH /api/v1/admin/governance/domains/{id}" => {
            let domain = governance_domain_fixture(fx).await;
            let id = id_of(&domain);
            request(
                "PATCH",
                &format!("/api/v1/admin/governance/domains/{id}"),
                t,
                Some(json!({"description": uniq("updated"), "row_version": 0})),
            )
        }
        "POST /api/v1/admin/governance/domains/{id}/entities" => {
            let domain = governance_domain_fixture(fx).await;
            let id = id_of(&domain);
            request(
                "POST",
                &format!("/api/v1/admin/governance/domains/{id}/entities"),
                t,
                Some(json!({"entity_logicalnames": [fx.entity]})),
            )
        }
        "DELETE /api/v1/admin/governance/domains/{id}/entities/{entity_logicalname}" => {
            let domain = governance_domain_fixture(fx).await;
            let id = id_of(&domain);
            admin(
                fx,
                "POST",
                &format!("/api/v1/admin/governance/domains/{id}/entities"),
                Some(json!({"entity_logicalnames": [fx.entity]})),
            )
            .await;
            request(
                "DELETE",
                &format!(
                    "/api/v1/admin/governance/domains/{id}/entities/{}",
                    fx.entity
                ),
                t,
                None,
            )
        }
        // ── audit-10-10 Phase 3.7 part J (calendars/metadata/rules/entity-adjacent leftovers) ──
        "POST /api/v1/admin/jobs/{id}/replay" => {
            let job_id = uniq("dead-letter-job");
            sqlx::query(
                "INSERT INTO apalis.jobs (job, id, job_type, status) \
                 VALUES ($1, $2, 'EngineJob', 'Killed')",
            )
            .bind(json!({}))
            .bind(&job_id)
            .execute(&fx.base.db)
            .await
            .expect("insert throwaway dead-letter job");
            request(
                "POST",
                &format!("/api/v1/admin/jobs/{job_id}/replay"),
                t,
                None,
            )
        }
        // BJB-6c: discarding a dead letter (09d37bf78 made it a mandatory
        // `Configuration`/`HardDelete` event).
        "DELETE /api/v1/admin/jobs/{id}" => {
            let job_id = uniq("dead-letter-discard");
            sqlx::query(
                "INSERT INTO apalis.jobs (job, id, job_type, status) \
                 VALUES ($1, $2, 'EngineJob', 'Killed')",
            )
            .bind(json!({}))
            .bind(&job_id)
            .execute(&fx.base.db)
            .await
            .expect("insert throwaway dead-letter job");
            request("DELETE", &format!("/api/v1/admin/jobs/{job_id}"), t, None)
        }
        // Z7-T4: cancelling a running batch job (a `Configuration`/`Update`).
        "POST /api/v1/jobs/{id}/cancel" => {
            let mut conn = fx.base.db.acquire().await.expect("connection");
            let id = attome_jobs::batch::start(&mut conn, "emission.batch", Some(1), None)
                .await
                .expect("start a throwaway batch");
            request("POST", &format!("/api/v1/jobs/{id}/cancel"), t, None)
        }
        // M06 W1 follow-up: entity-trigger dead letters (migration 0510). The
        // throwaway row names an entity no workflow watches, so the replay
        // dispatches nothing and succeeds.
        "POST /api/v1/workflow/trigger-dead-letters/{event_id}/replay"
        | "DELETE /api/v1/workflow/trigger-dead-letters/{event_id}" => {
            let event_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO workflow_trigger_failure \
                     (event_id, entity_logicalname, record_id, operation, last_error, \
                      dead_lettered_at) \
                 VALUES ($1, $2, $3, 'create', 'emission test', now())",
            )
            .bind(event_id)
            .bind(uniq("no_such_entity"))
            .bind(Uuid::now_v7())
            .execute(&fx.base.db)
            .await
            .expect("insert throwaway workflow trigger dead letter");
            let path = format!("/api/v1/workflow/trigger-dead-letters/{event_id}");
            if key.starts_with("POST") {
                request("POST", &format!("{path}/replay"), t, None)
            } else {
                request("DELETE", &path, t, None)
            }
        }
        "POST /api/v1/admin/legal-holds" => request(
            "POST",
            "/api/v1/admin/legal-holds",
            t,
            Some(json!({
                "entity_logicalname": fx.entity,
                "record_id": fx.record_id,
                "matter_reference": uniq("matter"),
            })),
        ),
        "POST /api/v1/admin/legal-holds/{id}/release" => {
            let placed = admin(
                fx,
                "POST",
                "/api/v1/admin/legal-holds",
                Some(json!({
                    "entity_logicalname": fx.entity,
                    "record_id": fx.record_id,
                    "matter_reference": uniq("matter"),
                })),
            )
            .await;
            let id = id_of(&placed);
            request(
                "POST",
                &format!("/api/v1/admin/legal-holds/{id}/release"),
                t,
                None,
            )
        }
        "POST /api/v1/consents/capture" => {
            let key = uniq_purpose_key(fx).await;
            request(
                "POST",
                "/api/v1/consents/capture",
                None,
                Some(json!({
                    "purpose_key": key,
                    "subject_reference": uniq("subject"),
                })),
            )
        }
        "POST /api/v1/consents/preference-links" => request(
            "POST",
            "/api/v1/consents/preference-links",
            t,
            Some(json!({"subject_entity": "contact", "subject_id": Uuid::now_v7()})),
        ),
        "POST /api/v1/consents/preferences" => {
            // E26-T1: a link for a contact, then a change through it.
            let key = uniq_purpose_key(fx).await;
            let link = admin(
                fx,
                "POST",
                "/api/v1/consents/preference-links",
                Some(json!({"subject_entity": "contact", "subject_id": Uuid::now_v7()})),
            )
            .await;
            request(
                "POST",
                "/api/v1/consents/preferences",
                None,
                Some(json!({
                    "token": link["token"],
                    "changes": [{"purpose_key": key, "channel": "email", "grant": true}],
                })),
            )
        }
        "POST /api/v1/consents/withdraw" => {
            let key = uniq_purpose_key(fx).await;
            request(
                "POST",
                "/api/v1/consents/withdraw",
                t,
                Some(json!({
                    "purpose_key": key,
                    "subject_reference": uniq("subject"),
                })),
            )
        }
        // ── business rules (D-789 §6.1; D-790 removed /admin/rules*) ─────────
        "POST /api/v1/admin/business-rules" => request(
            "POST",
            "/api/v1/admin/business-rules",
            t,
            Some(rule_body(fx, &uniq("rule"), "USD")),
        ),
        "PATCH /api/v1/admin/business-rules/{id}" => {
            let id = rule(fx).await;
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/business-rules/{id}"),
                    t,
                    Some(json!({
                        "policies": [ { "type": "set_value", "field": "title",
                                        "value": "EUR", "mode": "default" } ],
                    })),
                ),
                0,
            )
        }
        "DELETE /api/v1/admin/business-rules/{id}" => {
            let id = rule(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/business-rules/{id}"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/business-rules/{id}/publish" => {
            let id = rule(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/business-rules/{id}/publish"),
                t,
                None,
            )
        }
        // ── migration projects ──────────────────────────────────────────────
        "POST /api/v1/admin/migration-projects" => request(
            "POST",
            "/api/v1/admin/migration-projects",
            t,
            Some(json!({
                "name": uniq("migration-project"),
                "source_kind": "csv",
                "target_entity": fx.entity,
            })),
        ),
        "PUT /api/v1/admin/migration-projects/{id}" => {
            let id = migration_project(fx).await;
            request(
                "PUT",
                &format!("/api/v1/admin/migration-projects/{id}"),
                t,
                Some(json!({"name": uniq("migration-renamed"), "status": "active"})),
            )
        }
        "DELETE /api/v1/admin/migration-projects/{id}" => {
            let id = migration_project(fx).await;
            request(
                "DELETE",
                &format!("/api/v1/admin/migration-projects/{id}"),
                t,
                None,
            )
        }
        // ── recovery archive (D-788 rule 9; security review L1/L2) ──────────
        // Each restore writes its Configuration/Update event in its own
        // transaction, so the driver archives a value for an empty record.
        "POST /api/v1/admin/metadata/recovery-archive/{archive_id}/restore" => {
            let id = archived_value(fx).await;
            request(
                "POST",
                &format!("/api/v1/admin/metadata/recovery-archive/{id}/restore"),
                t,
                None,
            )
        }
        // ── release report (D-788 Topic 14, D-791) ─────────────────────────
        // Each decision writes its Configuration/Update event in its own
        // transaction; Restore through the recovery archive's restore.
        "POST /api/v1/admin/metadata/release-report-items/{item_id}/accept" => {
            let (id, _) = conflict_item(fx).await;
            with_if_match(
                request(
                    "POST",
                    &format!("/api/v1/admin/metadata/release-report-items/{id}/accept"),
                    t,
                    None,
                ),
                0,
            )
        }
        "POST /api/v1/admin/metadata/release-report-items/{item_id}/use-mine" => {
            let (id, record_row_version) = conflict_item(fx).await;
            with_if_match(
                request(
                    "POST",
                    &format!("/api/v1/admin/metadata/release-report-items/{id}/use-mine"),
                    t,
                    Some(json!({ "record_row_version": record_row_version })),
                ),
                0,
            )
        }
        "POST /api/v1/admin/metadata/release-report-items/{item_id}/dismiss" => {
            let id = report_item(
                fx,
                attome_core::release_report::ItemKind::BreakingApiChange,
                None,
                None,
            )
            .await;
            with_if_match(
                request(
                    "POST",
                    &format!("/api/v1/admin/metadata/release-report-items/{id}/dismiss"),
                    t,
                    None,
                ),
                0,
            )
        }
        "POST /api/v1/admin/metadata/release-report-items/{item_id}/restore" => {
            // An archived value of an emptied record; the field_deleted item
            // links it (same entity, field, reason, no changeset).
            archived_value(fx).await;
            let id = report_item(
                fx,
                attome_core::release_report::ItemKind::FieldDeleted,
                None,
                None,
            )
            .await;
            request(
                "POST",
                &format!("/api/v1/admin/metadata/release-report-items/{id}/restore"),
                t,
                None,
            )
        }
        "POST /api/v1/admin/metadata/recovery-archive/restore" => {
            archived_value(fx).await;
            request(
                "POST",
                "/api/v1/admin/metadata/recovery-archive/restore",
                t,
                Some(json!({"entity": fx.entity, "field": "title"})),
            )
        }
        // ── break-glass (P-environment-promotion §4) ────────────────────────
        "POST /api/v1/admin/metadata/break-glass" => request(
            "POST",
            "/api/v1/admin/metadata/break-glass",
            t,
            Some(json!({"ttl_minutes": 5})),
        ),
        "DELETE /api/v1/admin/metadata/break-glass" => {
            // Closing is idempotent, but open first so the window really was
            // open when it closed.
            admin(
                fx,
                "POST",
                "/api/v1/admin/metadata/break-glass",
                Some(json!({"ttl_minutes": 5})),
            )
            .await;
            request("DELETE", "/api/v1/admin/metadata/break-glass", t, None)
        }
        // ── changesets (Solution 7, D-785) ──────────────────────────────────
        // Each driver authors as its own administrator: an open changeset is
        // "the caller's own" for every later metadata write by its author
        // (design §4.3), so opening one as `fx.admin_token` would pull every
        // later driver's write into it.
        "POST /api/v1/admin/changesets" => {
            let author = changeset_author(fx).await;
            request(
                "POST",
                "/api/v1/admin/changesets",
                Some(&author),
                Some(changeset_open_body()),
            )
        }
        "POST /api/v1/admin/changesets/{id}/close" => {
            let author = changeset_author(fx).await;
            let id = open_changeset(fx, &author).await;
            // One recorded write, named by the header: close refuses an
            // empty changeset.
            let mut write = request(
                "POST",
                "/api/v1/admin/apps",
                Some(&author),
                Some(json!({"name": uniq("changeset-app")})),
            );
            write.headers_mut().insert(
                "x-attome-changeset",
                id.to_string().parse().expect("changeset header"),
            );
            call(fx, write).await;
            let detail = call(
                fx,
                request(
                    "GET",
                    &format!("/api/v1/admin/changesets/{id}"),
                    Some(&author),
                    None,
                ),
            )
            .await;
            let version = detail["changeset"]["row_version"]
                .as_i64()
                .expect("row_version");
            with_if_match(
                request(
                    "POST",
                    &format!("/api/v1/admin/changesets/{id}/close"),
                    Some(&author),
                    None,
                ),
                version,
            )
        }
        "POST /api/v1/admin/changesets/{id}/abandon" => {
            let author = changeset_author(fx).await;
            let id = open_changeset(fx, &author).await;
            request(
                "POST",
                &format!("/api/v1/admin/changesets/{id}/abandon"),
                Some(&author),
                None,
            )
        }
        "POST /api/v1/admin/metadata/changesets/plan" => {
            let document: Value = serde_json::from_str(CHANGESET_FIXTURE)
                .expect("the valid changeset fixture parses");
            request(
                "POST",
                "/api/v1/admin/metadata/changesets/plan",
                t,
                Some(json!({"changesets": [document]})),
            )
        }
        _ => return None,
    };
    Some((req, None))
}

/// A valid, checksummed `attome-changeset/v1` document (the format tooling's
/// own fixture). Planning it only writes `planned` ledger rows.
const CHANGESET_FIXTURE: &str = include_str!(
    "../../../../scripts/changesets/fixtures/valid/project/acme/0001-acme-contracts.json"
);

fn changeset_open_body() -> Value {
    let hex = Uuid::now_v7().simple().to_string();
    json!({
        "layer": "project",
        "scope": "audit-emit",
        "name": format!("audit-emit-{}", &hex[hex.len() - 12..]),
        "title": "Audit emission",
    })
}

/// A fresh `system.admin` user's session token, for the changeset drivers.
async fn changeset_author(fx: &Fx) -> String {
    let (user_id, _) = seed_user(&fx.base, "changeset-author").await;
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = 'system.admin'",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(&fx.base.db)
    .await
    .expect("grant system.admin to the changeset author");
    session_token(&fx.base, user_id, true).await
}

/// Opens a changeset as `author`; returns its id.
async fn open_changeset(fx: &Fx, author: &str) -> Uuid {
    let body = call(
        fx,
        request(
            "POST",
            "/api/v1/admin/changesets",
            Some(author),
            Some(changeset_open_body()),
        ),
    )
    .await;
    id_of(&body)
}

/// `access` -> `Access`, `soft_delete` -> `SoftDelete`: the serde variant name.
fn pascal(wire: &str) -> String {
    wire.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// Rows for `(category, operation)` on either write path.
async fn event_count(db: &attome_db::DbPool, category: &str, operation: &str) -> i64 {
    let c: AuditCategory =
        serde_json::from_value(json!(pascal(category))).expect("known AuditCategory");
    let o: AuditOperation =
        serde_json::from_value(json!(pascal(operation))).expect("known AuditOperation");
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE category = $1 AND operation = $2) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'category' = $3 AND payload->>'operation' = $4)",
    )
    .bind(c as i32)
    .bind(o as i32)
    .bind(pascal(category))
    .bind(pascal(operation))
    .fetch_one(db)
    .await
    .expect("count audit events")
}

/// `(METHOD /path, primary (category, operation))` for every mandatory mapping.
fn mandatory_mappings() -> Vec<(String, String, String)> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../openapi.json");
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}")),
    )
    .expect("openapi.json parses");
    let mut out = Vec::new();
    for (route, item) in doc["paths"].as_object().expect("paths") {
        for (method, op) in item.as_object().expect("path item") {
            let Some(audit) = op.get("x-audit") else {
                continue;
            };
            if audit["policy"] != "mandatory" {
                continue;
            }
            let primary = &audit["events"][0];
            out.push((
                format!("{} {route}", method.to_uppercase()),
                primary["category"].as_str().expect("category").to_owned(),
                primary["operation"].as_str().expect("operation").to_owned(),
            ));
        }
    }
    out.sort();
    out
}

/// Runs on its own thread with a 16 MiB stack: driving every mapped route
/// through the full router nests deep enough to overflow the default 2 MiB
/// test-thread stack in a debug build (0xc00000fd on Windows).
#[test]
fn every_mapped_security_route_writes_its_event() {
    std::thread::Builder::new()
        .name("every_mapped_security_route_writes_its_event".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build the test runtime")
                .block_on(every_mapped_security_route_writes_its_event_body());
        })
        .expect("spawn the large-stack test thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn every_mapped_security_route_writes_its_event_body() {
    let fx = skip_if_no_db!(fixture().await);
    let mappings = mandatory_mappings();
    assert!(
        !mappings.is_empty(),
        "openapi.json declares no mandatory x-audit mapping"
    );

    for (route, _) in UNDRIVABLE {
        assert!(
            mappings.iter().any(|(key, _, _)| key == route),
            "UNDRIVABLE lists {route}, which is no longer a mapped mandatory route"
        );
    }

    let mut failures = Vec::new();
    let mut driven = 0;
    for (key, category, operation) in &mappings {
        if UNDRIVABLE.iter().any(|(route, _)| route == key) {
            continue;
        }
        // Boxed: `drive` is one ~200-arm match, and its future overflows a
        // debug-build test thread's stack if it is polled in place.
        let Some((req, expected)) = Box::pin(drive(&fx, key)).await else {
            failures.push(format!(
                "{key}: no driver in audit_coverage_emission::drive"
            ));
            continue;
        };
        let before = event_count(&fx.base.db, category, operation).await;
        let res = fx.app.clone().oneshot(req).await.expect("send");
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        // A module-configuration change narrows this node's licence; restore
        // it so later routes stay mounted.
        fx.xrm.modules.store(full_license());
        let status_ok = match expected {
            Some(expected) => status == expected,
            None => status.is_success(),
        };
        if !status_ok {
            failures.push(format!(
                "{key}: {status} {}",
                String::from_utf8_lossy(&body)
            ));
            continue;
        }
        let after = event_count(&fx.base.db, category, operation).await;
        if after <= before {
            failures.push(format!(
                "{key}: succeeded ({status}) but wrote no {category}+{operation} event"
            ));
        }
        driven += 1;
    }

    eprintln!(
        "audit_coverage_emission: {} mandatory mappings, {driven} driven, {} undrivable, {} failed",
        mappings.len(),
        UNDRIVABLE.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} of {} mandatory mappings failed ({driven} driven):\n{}",
        failures.len(),
        mappings.len(),
        failures.join("\n")
    );
}

/// `Security` + `FailedLogin` rows naming `user_id` as the record, on either
/// write path.
async fn failed_logins_for(db: &attome_db::DbPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header \
                 WHERE category = $1 AND operation = $2 AND record_id = $3) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'category' = 'Security' \
                   AND payload->>'operation' = 'FailedLogin' \
                   AND payload->>'record_id' = $4)",
    )
    .bind(AuditCategory::Security as i32)
    .bind(AuditOperation::FailedLogin as i32)
    .bind(user_id)
    .bind(user_id.to_string())
    .fetch_one(db)
    .await
    .expect("count failed-login events")
}

/// A six-digit code that differs from `right` in its leading digit.
fn wrong_code(right: &str) -> String {
    let n: u32 = right.parse().expect("numeric TOTP code");
    format!("{:06}", (n + 500_000) % 1_000_000)
}

/// Audit plan 3.4: a rejected second factor writes `Security` + `FailedLogin`
/// naming the account, but only when the pending token itself verifies — an
/// unsigned token names nobody the server can vouch for, so it writes nothing.
#[tokio::test]
async fn failed_second_factor_attempts_are_audited() {
    let fx = skip_if_no_db!(fixture().await);

    // A wrong TOTP code against a valid pending-login token.
    let (user, totp) = enrolled_user(&fx, "failed-verify").await;
    let token = pending_token(&fx, user, attome_auth::TokenType::MfaPendingLogin).await;
    let before = failed_logins_for(&fx.base.db, user).await;
    let res = fx
        .app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/auth/mfa/verify",
            None,
            Some(json!({
                "pending_token": token,
                "code": wrong_code(&code_at_offset(&totp, 30)),
            })),
        ))
        .await
        .expect("send");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        failed_logins_for(&fx.base.db, user).await,
        before + 1,
        "a wrong code on a valid pending token must write one FailedLogin event"
    );

    // An unsigned token naming a real enrolled account.
    let (forged_user, forged_totp) = enrolled_user(&fx, "failed-forged").await;
    let now = chrono::Utc::now().timestamp();
    let forged = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(
            json!({
                "sub": forged_user,
                "typ": "mfa_pending_login",
                "iat": now,
                "exp": now + 300,
                "jti": Uuid::now_v7(),
            })
            .to_string(),
        ),
    );
    let before = failed_logins_for(&fx.base.db, forged_user).await;
    let res = fx
        .app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/auth/mfa/verify",
            None,
            Some(json!({
                "pending_token": forged,
                "code": wrong_code(&code_at_offset(&forged_totp, 30)),
            })),
        ))
        .await
        .expect("send");
    assert!(
        !res.status().is_success(),
        "an unsigned pending token must be refused, got {}",
        res.status()
    );
    assert_eq!(
        failed_logins_for(&fx.base.db, forged_user).await,
        before,
        "an unverifiable pending token must write no FailedLogin event"
    );

    // A wrong code on the self-service disable route.
    let (disabler, disabler_totp) = enrolled_user(&fx, "failed-disable").await;
    let session = session_token(&fx.base, disabler, false).await;
    let before = failed_logins_for(&fx.base.db, disabler).await;
    let res = fx
        .app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/auth/mfa/disable",
            Some(&session),
            Some(json!({"code": wrong_code(&code_at_offset(&disabler_totp, 30))})),
        ))
        .await
        .expect("send");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        failed_logins_for(&fx.base.db, disabler).await,
        before + 1,
        "a wrong code on /mfa/disable must write one FailedLogin event"
    );
}

/// D-541 rule 4 / I4: `audit_config` governs record and field capture only.
/// With every operation disabled for the role-assignment table and globally,
/// a role grant still writes its `Access` + `Grant` event.
#[tokio::test]
async fn a_role_grant_is_audited_with_entity_audit_config_off() {
    let fx = skip_if_no_db!(fixture().await);
    for entity in [Some("user_account_mm_role"), None] {
        sqlx::query(
            "INSERT INTO audit_config \
             (organization_ref, entity_name, operation_mask, is_audited, capture_snapshot) \
             VALUES (NULL, $1, 0, false, false)",
        )
        .bind(entity)
        .execute(&fx.base.db)
        .await
        .expect("disable audit capture");
    }

    let (user, _) = seed_user(&fx.base, "bypass").await;
    let rid = role(&fx).await;
    let before = event_count(&fx.base.db, "access", "grant").await;
    call(
        &fx,
        request(
            "POST",
            &format!("/api/v1/admin/security/users/{user}/roles"),
            Some(&fx.admin_token),
            Some(json!({"role_id": rid})),
        ),
    )
    .await;
    let after = event_count(&fx.base.db, "access", "grant").await;
    assert_eq!(
        after,
        before + 1,
        "the mandatory Access+Grant event must be written regardless of audit_config"
    );
    let _ = fx.admin_id;
}

async fn app_fixture(fx: &Fx) -> Value {
    admin(
        fx,
        "POST",
        "/api/v1/admin/apps",
        Some(json!({"name": uniq("app")})),
    )
    .await
}

async fn event_subscription_fixture(fx: &Fx) -> Value {
    admin(
        fx,
        "POST",
        "/api/v1/admin/events/subscriptions",
        Some(json!({
            "name": uniq("sub"),
            "kind": "webhook",
            "target_url": SAFE_WEBHOOK_URL,
            "owner_ref": fx.admin_id,
        })),
    )
    .await
}

async fn governance_domain_fixture(fx: &Fx) -> Value {
    admin(
        fx,
        "POST",
        "/api/v1/admin/governance/domains",
        Some(json!({"name": uniq("domain")})),
    )
    .await
}

/// `add_suppression` returns `204` with no body, so the row's id is read
/// back from the list endpoint by the email it was created with.
async fn email_suppression_fixture(fx: &Fx) -> (String, Uuid) {
    let email = format!("{}@example.com", uniq("suppress"));
    admin(
        fx,
        "POST",
        "/api/v1/admin/email/suppressions",
        Some(json!({"email": email})),
    )
    .await;
    let list = admin(
        fx,
        "GET",
        "/api/v1/admin/email/suppressions?page=1&page_size=200",
        None,
    )
    .await;
    let id = list["items"]
        .as_array()
        .expect("suppression list has items")
        .iter()
        .find(|i| i["email"].as_str() == Some(email.as_str()))
        .map(id_of)
        .unwrap_or_else(|| panic!("suppression not found for {email}"));
    (email, id)
}

/// Inserted directly against the throwaway test database (one of
/// coding-guidelines.md's API-first exemptions) rather than through the
/// HTTP API, because a real delivery row only exists as a side effect of
/// `auth/register`/`reset/request`/an admin invitation — this is fixture
/// setup for the `resend` route under test, not a route under test itself.
async fn email_delivery_fixture(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&fx.base.db)
        .await
        .expect("begin delivery fixture tx");
    attome_email::delivery::record_queued_in_tx(
        &mut tx,
        id,
        attome_email::delivery::EmailDeliveryKind::EmailVerification,
        &format!("{}@example.com", uniq("resend")),
        "Verify your email",
        Some(fx.admin_id),
        None,
        None,
    )
    .await
    .expect("insert delivery fixture");
    attome_db::tx::commit(tx)
        .await
        .expect("commit delivery fixture");
    // A queued delivery is refused by resend (BEM-4); settle it first.
    attome_email::delivery::mark_sent(&fx.base.db, id)
        .await
        .expect("settle delivery fixture");
    id
}

/// A fresh entity with `title` (text) and `status` (choice) fields — one per
/// caller, since each driven state-model route creates the entity's one
/// allowed active model (attome-state's own "one active model per entity"
/// guard) and they must not collide with each other.
async fn state_model_entity(fx: &Fx) -> String {
    let logicalname = format!("audit_emit_sm_{}", Uuid::now_v7().simple());
    let entity = admin(
        fx,
        "POST",
        "/api/v1/admin/entities",
        Some(json!({"logicalname": logicalname, "name": "Audit Emission State"})),
    )
    .await;
    let entity_id = id_of(&entity);
    admin(
        fx,
        "POST",
        &format!("/api/v1/admin/entities/{entity_id}/fields"),
        Some(json!({
            "logicalname": "status", "name": "Status", "field_type": "choice",
            "options": {"choices": ["new", "active", "done"], "multi": false},
        })),
    )
    .await;
    logicalname
}

/// A state model (`new -> active`) on a fresh entity, with one transition.
/// Returns the model and transition response bodies (their `id`/`row_version`).
async fn state_model_with_transition(fx: &Fx) -> (Value, Value) {
    let entity = state_model_entity(fx).await;
    let model = admin(
        fx,
        "POST",
        "/api/v1/admin/state-models",
        Some(json!({
            "entity_logicalname": entity, "name": "Audit Emission Lifecycle",
            "state_field": "status", "initial_state": "new", "is_active": true,
        })),
    )
    .await;
    let transition = admin(
        fx,
        "POST",
        &format!("/api/v1/admin/state-models/{}/transitions", id_of(&model)),
        Some(json!({"from_state": "new", "to_state": "active", "name": "Start"})),
    )
    .await;
    (model, transition)
}

/// A minimal graph with one manual `Trigger` node and nothing else —
/// `graph::validate` requires only that the graph be well-formed and have an
/// entry point (a `Trigger` node), which a lone node with no edges is.
fn trigger_only_graph() -> Value {
    json!({
        "nodes": [{"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}}],
        "edges": [],
    })
}

/// `trigger_only_graph` plus a long `wait` node, so a started instance parks
/// in `waiting` rather than completing immediately on the trigger alone —
/// needed to drive the cancel route, which only accepts a `running`/`waiting`
/// instance.
fn waiting_workflow_graph() -> Value {
    json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "w", "type": "wait", "config": {"delay_seconds": 999_999}},
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "w", "to_port": "in"},
        ],
    })
}

/// A fresh workflow definition — one per caller so `logicalname` never
/// collides with another driven route.
async fn workflow_definition(fx: &Fx) -> Value {
    let logicalname = format!("audit_emit_wf_{}", Uuid::now_v7().simple());
    admin(
        fx,
        "POST",
        "/api/v1/workflow/definitions",
        Some(json!({"logicalname": logicalname, "name": "Audit Emission Workflow"})),
    )
    .await
}

/// A fresh definition with one draft version (`trigger_only_graph`).
async fn workflow_definition_with_version(fx: &Fx) -> (Value, Value) {
    let def = workflow_definition(fx).await;
    let version = admin(
        fx,
        "POST",
        &format!("/api/v1/workflow/definitions/{}/versions", id_of(&def)),
        Some(json!({"graph": trigger_only_graph()})),
    )
    .await;
    (def, version)
}

/// A fresh definition with a published version whose graph parks a started
/// instance in `waiting` (`waiting_workflow_graph`). Returns the
/// definition's logicalname, ready for `POST /workflow/instances`.
async fn published_workflow(fx: &Fx) -> String {
    let logicalname = format!("audit_emit_wf_{}", Uuid::now_v7().simple());
    let def = admin(
        fx,
        "POST",
        "/api/v1/workflow/definitions",
        Some(json!({"logicalname": logicalname, "name": "Audit Emission Workflow"})),
    )
    .await;
    let def_id = id_of(&def);
    let version = admin(
        fx,
        "POST",
        &format!("/api/v1/workflow/definitions/{def_id}/versions"),
        Some(json!({"graph": waiting_workflow_graph()})),
    )
    .await;
    admin(
        fx,
        "POST",
        &format!(
            "/api/v1/workflow/definitions/{def_id}/versions/{}/publish",
            id_of(&version)
        ),
        None,
    )
    .await;
    logicalname
}

/// A stored customer test with an empty (always passing) definition, at
/// row_version 1.
async fn customer_test(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO customer_test (id, name, definition) VALUES ($1, $2, '{}'::jsonb)")
        .bind(id)
        .bind(format!("emission-{id}"))
        .execute(&fx.base.db)
        .await
        .expect("seed a customer test");
    id
}

/// Sets `If-Match` to `row_version`, as every content page/space/template
/// update route requires (D-079).
fn with_if_match(mut req: Request<Body>, row_version: i64) -> Request<Body> {
    req.headers_mut().insert(
        header::IF_MATCH,
        format!("\"{row_version}\"")
            .parse()
            .expect("if-match header"),
    );
    req
}

async fn content_space(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/content/spaces",
            Some(json!({"name": uniq("content-space")})),
        )
        .await,
    )
}

/// A content page in its own space; returns `(id, row_version)`.
async fn content_page(fx: &Fx) -> (Uuid, i64) {
    let space_id = content_space(fx).await;
    let page = admin(
        fx,
        "POST",
        "/api/v1/admin/content/pages",
        Some(json!({
            "content_space_id": space_id,
            "title": uniq("page"),
            "url_path": format!("/{}", uniq("path")),
        })),
    )
    .await;
    let row_version = page["row_version"]
        .as_i64()
        .unwrap_or_else(|| panic!("content page has no row_version: {page}"));
    (id_of(&page), row_version)
}

async fn content_template(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/content/templates",
            Some(json!({"name": uniq("content-template"), "blocks": []})),
        )
        .await,
    )
}

/// A match rule on `fx.entity`'s `title` field; returns `(id, row_version)`.
async fn match_rule(fx: &Fx) -> (Uuid, i64) {
    let row = admin(
        fx,
        "POST",
        "/api/v1/admin/data/match-rules",
        Some(json!({
            "name": uniq("match-rule"),
            "entity": fx.entity,
            "fields": [{"field": "title", "comparator": "exact", "weight": 1.0}],
            "threshold": 0.9,
            "is_active": true,
            "auto_merge": false,
        })),
    )
    .await;
    let row_version = row["row_version"]
        .as_i64()
        .unwrap_or_else(|| panic!("match rule has no row_version: {row}"));
    (id_of(&row), row_version)
}

/// A survivorship rule on `fx.entity`'s `title` field.
async fn survivorship_rule(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/data/survivorship-rules",
            Some(json!({
                "entity": fx.entity,
                "field": "title",
                "strategy": "most_recent",
            })),
        )
        .await,
    )
}

/// A data mapping targeting `fx.entity`.
async fn data_mapping(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/data/mappings",
            Some(json!({
                "name": uniq("mapping"),
                "target_entity": fx.entity,
                "source_kind": "csv",
                "fields": [{"source": "Title", "target": "title"}],
            })),
        )
        .await,
    )
}

/// A second throwaway entity, distinct from `fx.entity` — relationships need
/// two.
async fn second_entity(fx: &Fx) -> String {
    let logicalname = format!("rel_{}", Uuid::now_v7().simple());
    admin(
        fx,
        "POST",
        "/api/v1/admin/entities",
        Some(json!({"logicalname": logicalname, "name": "Audit Emission Rel"})),
    )
    .await;
    let registry = attome_core::build_registry(&fx.base.db)
        .await
        .expect("build metadata registry");
    fx.xrm.entities.swap(registry);
    logicalname
}

/// A relationship between `fx.entity` and a fresh second entity.
async fn relationship(fx: &Fx) -> Value {
    let entity_b = second_entity(fx).await;
    admin(
        fx,
        "POST",
        "/api/v1/admin/relationships",
        Some(json!({
            "name": format!("rel_{}", Uuid::now_v7().simple()),
            "entity_a": fx.entity,
            "entity_b": entity_b,
            "role_a": "parent",
            "role_b": "child",
        })),
    )
    .await
}

/// A case definition on `fx.entity`.
async fn case_def(fx: &Fx) -> Value {
    admin(
        fx,
        "POST",
        "/api/v1/process/case-defs",
        Some(json!({"name": uniq("case-def"), "source": format!("entity:{}", fx.entity)})),
    )
    .await
}

/// A prediction model not currently training — inserted directly, since
/// creating one through the API always leaves it `training` (the create
/// route enqueues training in the same transaction as the insert), which
/// would make the retrain/retire routes below fail their own `status !=
/// 'training'` guard. Legitimate per coding-guidelines §4's "tests against a
/// throwaway database" exemption.
async fn idle_predict_model(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO prediction_model \
             (id, name, target, entity, algorithm, status, created_by) \
         VALUES ($1, $2, 'sla_breach', 'service_ticket', 'logistic_regression', \
                 'active', $3)",
    )
    .bind(id)
    .bind(uniq("predict-model-idle"))
    .bind(fx.admin_id)
    .execute(&fx.base.db)
    .await
    .expect("insert throwaway idle prediction model");
    id
}

/// A `proposed` retention action — inserted directly, since the only route
/// that creates one is the daily propose sweep, which needs real aged data
/// this throwaway database has none of. Legitimate per coding-guidelines
/// §4's "tests against a throwaway database" exemption.
async fn retention_action(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO audit_retention_action (id, action_type, target, status) \
         VALUES ($1, 'partition_archive', $2, 'proposed')",
    )
    .bind(id)
    .bind(uniq("retention-target"))
    .execute(&fx.base.db)
    .await
    .expect("insert throwaway retention action");
    id
}

/// A retention rule on the fixture entity — inserted directly (a throwaway
/// database, coding-guidelines §4) so the update and delete drivers each
/// have their own.
async fn retention_rule(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO retention_rule (id, name, entity_logicalname, period_days, action)          VALUES ($1, $2, $3, 365, 'review')",
    )
    .bind(id)
    .bind(uniq("rule"))
    .bind(&fx.entity)
    .execute(&fx.base.db)
    .await
    .expect("insert throwaway retention rule");
    id
}

/// Creates a fresh, active consent purpose and returns its `key` (not its
/// id — `capture`/`withdraw` both take the key, not the row).
async fn uniq_purpose_key(fx: &Fx) -> String {
    let key = uniq("purpose");
    admin(
        fx,
        "POST",
        "/api/v1/audit_consent_purpose",
        Some(json!({"key": key, "lawful_basis": "consent"})),
    )
    .await;
    key
}

/// A public IP literal (no DNS lookup needed, hermetic in a sandboxed test
/// environment) that `attome_server::ssrf_guard::validate_url` accepts — same
/// URL `attome-events/tests/ssrf.rs`'s positive case uses.
const SAFE_WEBHOOK_URL: &str = "https://8.8.8.8/webhook";

/// A business rule body on `fx.entity`: always, set `title` on create when
/// empty (the text constant matches `title`'s type).
fn rule_body(fx: &Fx, name: &str, value: &str) -> Value {
    json!({
        "entity": fx.entity,
        "name": name,
        "condition": { "all": [] },
        "policies": [ { "type": "set_value", "field": "title", "value": value,
                        "mode": "default" } ],
    })
}

/// A business rule on `fx.entity` (`row_version` 0).
async fn rule(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/business-rules",
            Some(rule_body(fx, &uniq("rule"), "USD")),
        )
        .await,
    )
}

/// A migration project targeting `fx.entity`.
async fn migration_project(fx: &Fx) -> Uuid {
    id_of(
        &admin(
            fx,
            "POST",
            "/api/v1/admin/migration-projects",
            Some(json!({
                "name": uniq("migration-project"),
                "source_kind": "csv",
                "target_entity": fx.entity,
            })),
        )
        .await,
    )
}
