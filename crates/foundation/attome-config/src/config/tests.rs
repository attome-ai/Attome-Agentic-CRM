// ── Tests (D-038 — placeholder expansion + fail-fast reporting) ───────────────

use super::{
    AnchorStoreSection, ApiKeyPepper, AppConfig, AuditSection, CacheRole, CacheRoleOverride,
    CacheSentinelConfig, CacheSentinelNode, CaptchaConfig, CaptchaProvider, ConfigError,
    DatabasePoolSize, DatabasePools, MigratorDbCredentials, OidcProviderConfig, PortalSection,
    ReadonlyDbCredentials, RuntimeDbCredentials, cidr_contains, default_oidc_email_claim,
    default_oidc_scopes, expand_env_vars, expand_env_vars_in_value, parse_cidr,
};
use crate::keyring::KeyRing;

/// Minimal valid config — every section filled with throwaway test
/// values, `auth.jwt_secret` long enough to pass `check_secret`.
///
/// Kept as a named constant (not just a function-local literal) so a test
/// that needs to rewrite exactly one field can parse it into a
/// `serde_json::Value`, change that one path, and still prove `from_file`
/// handles the rest of the document unchanged (BCF-P0.4).
const MINIMAL_VALID_JSON: &str = r#"{
        "app": {
            "port": 0, "frontend_host": "localhost", "frontend_port": 4200
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
            "password": "test", "schema": "test", "connection_number": 1,
            "timeout": 5.0
        },
        "cache": {
            "host": "localhost", "port": 6379, "password": "", "db": 0,
            "connection_pool_size": 1, "timeout": 500
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
            "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
            "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
        },
        "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
        "observability": {
            "metrics_port": 0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "a@b.c",
            "smtp_from_name": "t", "smtp_use_tls": false
        },
        "google_ai": { "api_key": "test" }
    }"#;

fn minimal_valid_config() -> AppConfig {
    serde_json::from_str(MINIMAL_VALID_JSON).expect("test config must deserialize")
}

/// P-retention-archive-completion §6(a): a fresh deployment with no
/// `retention` block in its config must behave exactly as today — every
/// window `None` (keep forever), `legal_hold` off, and `dry_run` on, so
/// no archive/drop/purge action can execute until an operator opts in.
#[test]
fn retention_section_defaults_to_keep_forever_dry_run_and_no_legal_hold() {
    let config = minimal_valid_config();
    assert_eq!(config.retention.audit_days, None);
    assert_eq!(config.retention.s2s_access_log_days, None);
    assert_eq!(config.retention.entity_purge_grace_days, None);
    assert!(!config.retention.legal_hold);
    assert!(config.retention.dry_run);
    assert_eq!(config.retention.propose_interval_secs, 86400);
    // M23 Records Management (D-456): a fresh deployment must keep today's
    // entity_purge behavior with no config change required.
    assert_eq!(config.retention.disposition_action, "purge");
}

/// P-data-protection-governance §4 — a fresh deployment with no
/// `deployment` block must behave exactly as today: no residency claim
/// configured, so the region-assertion check in `validate()` is a no-op
/// regardless of `storage.s3_region`.
#[test]
fn deployment_data_region_defaults_to_none_and_validator_is_a_no_op() {
    let config = minimal_valid_config();
    assert_eq!(config.deployment.data_region, None);
    assert!(config.validate().is_ok());
}

/// P-data-protection-governance §4 — once an operator declares a residency
/// claim, it must match where the object store actually is.
#[test]
fn validate_rejects_a_data_region_that_does_not_match_s3_region() {
    let mut config = minimal_valid_config();
    // minimal_valid_config's storage.s3_region is "us-east-1".
    config.deployment.data_region = Some("eu-west-1".into());
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("deployment.data_region"));
}

/// attome-db hardening Phase 1.1 — `database.timeout` is the pool acquire
/// timeout in seconds. Zero, negative, non-finite, or absurdly large values
/// must fail boot rather than reach the pool builders. NaN and infinity are
/// set on the struct because JSON can't express them.
#[test]
fn validate_rejects_an_out_of_range_database_timeout() {
    for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 120.5] {
        let mut config = minimal_valid_config();
        config.database.timeout = bad;
        let err = config
            .validate()
            .expect_err(&format!("database.timeout {bad} must be rejected"));
        assert!(
            format!("{err}").contains("database.timeout"),
            "database.timeout {bad}: {err}"
        );
    }
}

/// Sub-second and boundary values stay valid — `0.5` in particular, which
/// attome-db used to truncate to a zero acquire timeout.
#[test]
fn validate_accepts_an_in_range_database_timeout() {
    for good in [0.5, 1.0, 120.0] {
        let mut config = minimal_valid_config();
        config.database.timeout = good;
        assert!(
            config.validate().is_ok(),
            "database.timeout {good} must be accepted: {:?}",
            config.validate()
        );
    }
}

#[test]
fn validate_rejects_an_out_of_range_database_connection_number() {
    for bad in [0u32, 1001] {
        let mut config = minimal_valid_config();
        config.database.connection_number = bad;
        let err = config.validate().expect_err(&format!(
            "database.connection_number {bad} must be rejected"
        ));
        assert!(
            format!("{err}").contains("database.connection_number"),
            "database.connection_number {bad}: {err}"
        );
    }
}

#[test]
fn validate_accepts_an_in_range_database_connection_number() {
    for good in [1u32, 1000] {
        let mut config = minimal_valid_config();
        config.database.connection_number = good;
        assert!(
            config.validate().is_ok(),
            "database.connection_number {good} must be accepted: {:?}",
            config.validate()
        );
    }
}

/// attome-db hardening Phase 2.3 — `database.pools` is optional: absent, every
/// pool entry is unset, so every pool keeps `connection_number`.
#[test]
fn database_pools_default_to_unset() {
    let config = minimal_valid_config();
    let pools = &config.database.pools;
    assert!(pools.runtime.is_none());
    assert!(pools.readonly.is_none());
    assert!(pools.readonly_primary.is_none());
    assert!(pools.migrator.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn database_pools_parse_per_pool_sizes() {
    let pools: DatabasePools = serde_json::from_value(serde_json::json!({
        "runtime": { "max_connections": 20 },
        "migrator": { "max_connections": 2 },
    }))
    .expect("database.pools must parse");
    assert_eq!(pools.runtime.map(|size| size.max_connections), Some(20));
    assert_eq!(pools.migrator.map(|size| size.max_connections), Some(2));
    assert!(pools.readonly.is_none());
    assert!(pools.readonly_primary.is_none());
}

/// Every pool entry gets the same `1..=1000` bound as `connection_number`,
/// and the error names the exact key.
#[test]
fn validate_rejects_an_out_of_range_pool_size() {
    let fields = ["runtime", "readonly", "readonly_primary", "migrator"];
    for field in fields {
        for bad in [0u32, 1001] {
            let mut config = minimal_valid_config();
            let size = Some(DatabasePoolSize {
                max_connections: bad,
            });
            match field {
                "runtime" => config.database.pools.runtime = size,
                "readonly" => config.database.pools.readonly = size,
                "readonly_primary" => config.database.pools.readonly_primary = size,
                _ => config.database.pools.migrator = size,
            }
            let err = config
                .validate()
                .expect_err(&format!("database.pools.{field} = {bad} must be rejected"));
            assert!(
                format!("{err}").contains(&format!("database.pools.{field}.max_connections")),
                "database.pools.{field} = {bad}: {err}"
            );
        }
    }
}

#[test]
fn validate_accepts_in_range_pool_sizes() {
    for good in [1u32, 1000] {
        let mut config = minimal_valid_config();
        let size = Some(DatabasePoolSize {
            max_connections: good,
        });
        config.database.pools.runtime = size;
        config.database.pools.readonly = size;
        config.database.pools.readonly_primary = size;
        config.database.pools.migrator = size;
        assert!(
            config.validate().is_ok(),
            "pool size {good} must be accepted: {:?}",
            config.validate()
        );
    }
}

/// Case-insensitive match — "US-EAST-1" and "us-east-1" name the same
/// region, an operator's casing shouldn't matter.
#[test]
fn validate_accepts_a_data_region_that_matches_s3_region_case_insensitively() {
    let mut config = minimal_valid_config();
    config.deployment.data_region = Some("US-EAST-1".into());
    assert!(config.validate().is_ok());
}

/// A config that omits an entire optional section (`s2s`/`audit`/
/// `jobs`, all `#[serde(default)]` on `AppConfig` itself) must fall back
/// to each field's own documented default — not to the section struct's
/// derived, all-zero `Default`. `minimal_valid_config`'s JSON above
/// already omits every one of these sections, so this pins that real
/// fixture's behavior directly rather than constructing a separate one.
/// Regression test for the bug found live in this session:
/// `jobs.run_worker_inline` would've silently become `false` (disabling
/// the inline job worker entirely) whenever `jobs` was omitted, under a
/// bare derived `Default`. Config-surface reduction (item 23) later
/// removed every field this test used to pin that was pure internal
/// tuning (never varied per-deployment) — `telemetry_buffer` was deleted
/// outright, and `s2s.nonce_ttl_secs`/`audit.chain_poll_interval_ms`/
/// `chain_batch_size`/`prune_interval_secs`/
/// `partition_maintenance_interval_secs`/`notification.new_user_backfill_days`
/// became Rust constants next to their call sites — so this test only
/// covers what's still config-driven.
#[test]
fn omitting_a_whole_optional_section_still_yields_its_documented_field_defaults() {
    let config = minimal_valid_config();

    assert_eq!(config.s2s.failure_alert_threshold, 100);
    assert!(config.s2s.access_log_enabled);

    assert_eq!(config.audit.partition_create_ahead_months, 2);

    assert_eq!(config.jobs.worker_concurrency, 10);
    assert_eq!(config.jobs.batch_worker_concurrency, 3);
    assert_eq!(config.jobs.history_retention_days, 30);
    assert!(config.jobs.run_worker_inline);
}

/// Z6-T1: the chosen storage backend must have its own settings; the other
/// backends' settings are not required.
#[test]
fn validate_requires_the_chosen_storage_backends_settings() {
    use crate::config::StorageBackend;

    let mut config = minimal_valid_config();
    config.storage.backend = StorageBackend::Local;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("storage.local.path"), "{err}");

    config.storage.local.path = "data/files".into();
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("storage.local.url_signing_key"), "{err}");

    config.storage.local.url_signing_key = "test-only-local-link-key-32-bytes-min".into();
    config.storage.s3_bucket = String::new();
    config.validate().expect("local needs no s3_* settings");

    config.storage.local.public_base_url = "not a url".into();
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("storage.local.public_base_url"), "{err}");

    config.storage.backend = StorageBackend::Azure;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("storage.azure.account"), "{err}");

    config.storage.backend = StorageBackend::Gcs;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("storage.gcs.bucket"), "{err}");

    config.storage.backend = StorageBackend::S3;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("storage.s3_bucket"), "{err}");
}

/// Z9-T3: a catalogue model needs a unique id, a known adapter, a context
/// size and a price of zero or more; allowed labels default to public and
/// internal.
#[test]
fn validate_checks_the_model_catalogue() {
    use crate::config::{CatalogueModel, DataLabel};

    let model = |id: &str| -> CatalogueModel {
        serde_json::from_value(serde_json::json!({ "id": id, "max_context": 8192 }))
            .expect("a catalogue model parses")
    };
    let mut config = minimal_valid_config();
    config.inference.catalogue = vec![model("small"), model("large")];
    config.validate().expect("two distinct models are valid");
    assert_eq!(
        config.inference.catalogue[0].allowed_labels,
        vec![DataLabel::Public, DataLabel::Internal]
    );
    assert_eq!(config.inference.catalogue[0].adapter, "openai_compatible");

    for (bad, needle) in [
        (vec![model("a"), model("a")], "listed twice"),
        (vec![model(" ")], "id must be set"),
        (
            vec![CatalogueModel {
                max_context: 0,
                ..model("a")
            }],
            "max_context",
        ),
        (
            vec![CatalogueModel {
                cost_per_1k_tokens: -1.0,
                ..model("a")
            }],
            "cost_per_1k_tokens",
        ),
        (
            vec![CatalogueModel {
                adapter: "bedrock".into(),
                ..model("a")
            }],
            "adapter",
        ),
        (
            vec![CatalogueModel {
                max_concurrent: Some(0),
                ..model("a")
            }],
            "max_concurrent",
        ),
    ] {
        config.inference.catalogue = bad;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    }
    assert!(DataLabel::Secret > DataLabel::Health && DataLabel::Health > DataLabel::Public);
}

/// Z5-T6: TLS is off by default; on, it needs both files and a known
/// minimum version.
#[test]
fn validate_checks_the_tls_files() {
    let mut config = minimal_valid_config();
    assert!(!config.app.tls.enabled);
    config.app.tls.enabled = true;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.cert_path"), "{err}");

    let dir = std::env::temp_dir().join(format!("attome-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    std::fs::write(&cert, "x").unwrap();
    config.app.tls.cert_path = cert.to_string_lossy().into_owned();
    config.app.tls.key_path = dir.join("missing.pem").to_string_lossy().into_owned();
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.key_path"), "{err}");

    config.app.tls.key_path = cert.to_string_lossy().into_owned();
    config.validate().expect("both files exist");
    config.app.tls.min_version = Some("1.1".into());
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.min_version"), "{err}");
    config.app.tls.min_version = Some("1.3".into());
    assert!(config.app.tls.tls13_only());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Z5-T7: ACME is off by default; on, it needs TLS on, a domain, a contact
/// address and an https directory, and no certificate files.
#[test]
fn acme_config_requires_domains() {
    let mut config = minimal_valid_config();
    assert!(!config.app.tls.acme.enabled);
    assert_eq!(
        config.app.tls.acme.directory_url,
        crate::config::LETS_ENCRYPT_DIRECTORY
    );
    config.app.tls.acme.enabled = true;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.acme.enabled"), "{err}");

    config.app.tls.enabled = true;
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.acme.domains"), "{err}");

    config.app.tls.acme.domains = vec!["crm.example.com".into()];
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.acme.contact_email"), "{err}");

    config.app.tls.acme.contact_email = "ops@example.com".into();
    config
        .validate()
        .expect("ACME needs no cert_path or key_path");
    config.app.tls.acme.directory_url = "http://acme.example/directory".into();
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("app.tls.acme.directory_url"), "{err}");
}

#[test]
fn storage_backend_defaults_to_s3_and_parses_by_name() {
    use crate::config::StorageBackend;

    assert_eq!(minimal_valid_config().storage.backend, StorageBackend::S3);
    let parsed: StorageBackend = serde_json::from_str("\"local\"").expect("parse");
    assert_eq!(parsed, StorageBackend::Local);
    assert!(serde_json::from_str::<StorageBackend>("\"ftp\"").is_err());
}

#[test]
fn validate_rejects_a_missing_apikey_hash_pepper() {
    let mut config = minimal_valid_config();
    config.auth.apikey_hash_pepper = String::new().into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.apikey_hash_pepper"));
}

#[test]
fn validate_rejects_a_too_short_apikey_hash_pepper() {
    let mut config = minimal_valid_config();
    config.auth.apikey_hash_pepper = "short".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.apikey_hash_pepper"));
}

#[test]
fn validate_rejects_a_duplicate_apikey_pepper_id() {
    let mut config = minimal_valid_config();
    // Default apikey_hash_pepper_id is 0 — a previous entry reusing 0
    // collides with the current pepper's own id.
    config.auth.apikey_hash_previous_peppers = vec![super::ApiKeyPepper {
        id: 0,
        secret: "another-throwaway-pepper-at-least-32-bytes".into(),
    }];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("duplicate pepper id"));
}

#[test]
fn validate_rejects_a_too_short_previous_apikey_pepper() {
    let mut config = minimal_valid_config();
    config.auth.apikey_hash_previous_peppers = vec![super::ApiKeyPepper {
        id: 1,
        secret: "short".into(),
    }];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("apikey_hash_previous_peppers"));
}

#[test]
fn validate_accepts_a_valid_pepper_ring_with_rotation() {
    let mut config = minimal_valid_config();
    config.auth.apikey_hash_pepper_id = 1;
    config.auth.apikey_hash_pepper = "current-throwaway-pepper-at-least-32-bytes".into();
    config.auth.apikey_hash_previous_peppers = vec![super::ApiKeyPepper {
        id: 0,
        secret: "retired-throwaway-pepper-at-least-32-bytes".into(),
    }];
    assert!(config.validate().is_ok());
}

#[test]
fn validate_passes_with_ssl_mode_defaulted_to_prefer() {
    let config = minimal_valid_config();
    assert_eq!(config.database.ssl_mode, "prefer");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_an_unknown_ssl_mode() {
    let mut config = minimal_valid_config();
    config.database.ssl_mode = "yolo".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("database.ssl_mode"));
}

#[test]
fn validate_passes_with_mfa_policy_defaulted_to_off_and_no_key_set() {
    let config = minimal_valid_config();
    assert_eq!(config.auth.mfa_policy, "off");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_an_unknown_mfa_policy() {
    let mut config = minimal_valid_config();
    config.auth.mfa_policy = "sometimes".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.mfa_policy"));
}

#[test]
fn validate_rejects_optional_mfa_policy_without_an_encryption_key() {
    let mut config = minimal_valid_config();
    config.auth.mfa_policy = "optional".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.mfa_encryption_key"));
}

#[test]
fn validate_rejects_required_mfa_policy_without_an_encryption_key() {
    let mut config = minimal_valid_config();
    config.auth.mfa_policy = "required".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.mfa_encryption_key"));
}

#[test]
fn validate_accepts_optional_mfa_policy_with_a_well_formed_key() {
    let mut config = minimal_valid_config();
    config.auth.mfa_policy = "optional".into();
    config.auth.mfa_encryption_key = KeyRing::single("ab".repeat(32));
    assert!(config.validate().is_ok());
}

#[test]
fn validate_passes_with_mfa_challenge_max_attempts_defaulted_to_five() {
    let config = minimal_valid_config();
    assert_eq!(config.auth.mfa_challenge_max_attempts, 5);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_a_zero_mfa_challenge_max_attempts() {
    let mut config = minimal_valid_config();
    config.auth.mfa_challenge_max_attempts = 0;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.mfa_challenge_max_attempts"));
}

#[test]
fn validate_passes_with_refresh_absolute_lifetime_defaulted_to_thirty_days() {
    let config = minimal_valid_config();
    assert_eq!(config.auth.refresh_absolute_lifetime_days, 30);
    assert!(config.validate().is_ok());
}

/// D-504: 0 would reject every refresh, and above 365 days migration 0462's
/// fallback anchor for an inconsistent lineage would no longer be expired.
#[test]
fn validate_bounds_refresh_absolute_lifetime_to_one_through_365_days() {
    for bad in [0, 366] {
        let mut config = minimal_valid_config();
        config.auth.refresh_absolute_lifetime_days = bad;
        let err = config.validate().unwrap_err();
        assert!(
            format!("{err}").contains("auth.refresh_absolute_lifetime_days"),
            "{bad} days: {err}"
        );
    }
    for good in [1, 365] {
        let mut config = minimal_valid_config();
        config.auth.refresh_absolute_lifetime_days = good;
        assert!(config.validate().is_ok(), "{good} days must be accepted");
    }
}

#[test]
fn validate_passes_with_registration_mode_defaulted_to_disabled() {
    let config = minimal_valid_config();
    assert_eq!(config.auth.registration_mode, "disabled");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_an_unknown_registration_mode() {
    let mut config = minimal_valid_config();
    config.auth.registration_mode = "sometimes".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.registration_mode"));
}

#[test]
fn validate_passes_with_idempotency_defaulted_to_empty_mandatory_list_and_24h_retention() {
    let config = minimal_valid_config();
    assert!(config.idempotency.mandatory_operations.is_empty());
    assert_eq!(config.idempotency.durable_retention_hours, 24);
    assert_eq!(config.idempotency.replay_max_bytes, 1024 * 1024);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_a_zero_hour_idempotency_durable_retention() {
    let mut config = minimal_valid_config();
    config.idempotency.durable_retention_hours = 0;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("idempotency.durable_retention_hours"));
}

#[test]
fn validate_rejects_a_zero_byte_idempotency_replay_cap() {
    let mut config = minimal_valid_config();
    config.idempotency.replay_max_bytes = 0;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("idempotency.replay_max_bytes"));
}

/// The replay cap bounds cached responses only; it is deliberately not tied to
/// `app.max_body_size_bytes` (the request limit), so a deployment with a small
/// request limit still validates with the default cap.
#[test]
fn validate_accepts_a_replay_cap_larger_than_the_request_body_limit() {
    let mut config = minimal_valid_config();
    config.app.max_body_size_bytes = 512 * 1024;
    config.idempotency.replay_max_bytes = 1024 * 1024;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_passes_with_change_feed_defaulted_to_30_day_retention() {
    let config = minimal_valid_config();
    assert_eq!(config.change_feed.retention_days, 30);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_a_non_positive_change_feed_retention_days() {
    let mut config = minimal_valid_config();
    config.change_feed.retention_days = 0;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("change_feed.retention_days"));

    config.change_feed.retention_days = -1;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("change_feed.retention_days"));
}

#[test]
fn validate_accepts_public_registration_mode() {
    let mut config = minimal_valid_config();
    config.auth.registration_mode = "public".into();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_invite_registration_mode() {
    let mut config = minimal_valid_config();
    config.auth.registration_mode = "invite".into();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_passes_with_erasure_disabled_and_no_key_set() {
    let config = minimal_valid_config();
    assert_eq!(config.audit.erasure_enabled, None);
    assert!(!config.audit.erasure_active());
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_erasure_enabled_without_an_encryption_key() {
    let mut config = minimal_valid_config();
    config.audit.erasure_enabled = Some(true);
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.erasure_key_encryption_key"));
}

#[test]
fn validate_accepts_erasure_enabled_with_a_well_formed_key() {
    let mut config = minimal_valid_config();
    config.audit.erasure_enabled = Some(true);
    config.audit.erasure_key_encryption_key = KeyRing::single("ab".repeat(32));
    assert!(config.validate().is_ok());
}

/// D-540 G2-2 a: an omitted `erasure_enabled` means "on wherever a key is
/// configured", and a configured key is format-checked like an explicit one.
#[test]
fn erasure_is_active_whenever_a_key_is_configured_unless_explicitly_disabled() {
    let mut config = minimal_valid_config();
    config.audit.erasure_key_encryption_key = KeyRing::single("ab".repeat(32));
    assert!(config.audit.erasure_active());
    assert!(config.validate().is_ok());

    config.audit.erasure_enabled = Some(false);
    assert!(!config.audit.erasure_active());
    assert!(config.validate().is_ok());

    config.audit.erasure_enabled = None;
    config.audit.erasure_key_encryption_key = KeyRing::single("too-short".into());
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.erasure_key_encryption_key"));
}

/// D-540 G2-2 a: config.example.json ships a development key, so development
/// runs the encrypted audit path by default.
#[test]
fn config_example_json_enables_audit_encryption_with_the_development_key() {
    let raw = include_str!("../../../../../config.example.json");
    let config: AppConfig =
        serde_json::from_str(raw).expect("config.example.json must deserialize into AppConfig");
    assert!(config.audit.erasure_active());
    assert_eq!(
        config.audit.erasure_key_encryption_key.active(),
        Some(crate::config::sections::audit::DEVELOPMENT_ERASURE_KEY)
    );
}

#[test]
fn validate_rejects_verify_full_without_a_root_cert() {
    let mut config = minimal_valid_config();
    config.database.ssl_mode = "verify-full".into();
    config.database.ssl_root_cert = None;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("database.ssl_root_cert"));
}

#[test]
fn validate_accepts_verify_full_with_a_root_cert_configured() {
    let mut config = minimal_valid_config();
    config.database.ssl_mode = "verify-full".into();
    config.database.ssl_root_cert = Some("/path/to/ca.pem".into());
    assert!(config.validate().is_ok());
}

// ── database.password (P-bootstrap-credential-scoping, D-204) ─────────────

#[test]
fn validate_rejects_migrate_on_boot_true_with_no_bootstrap_password() {
    let mut config = minimal_valid_config();
    config.database.migrate_on_boot = true;
    config.database.password = None;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("database.password"));
}

#[test]
fn validate_accepts_migrate_on_boot_false_with_no_bootstrap_password() {
    // The whole point of the fix (D-204): a `server`/`worker`-shaped
    // config that never reaches database_url()/direct_database_url()
    // (migrate_on_boot=false, the dedicated `migrate` binary handles
    // bootstrap separately) must be able to omit this credential
    // entirely — not merely leave it unused.
    let mut config = minimal_valid_config();
    config.database.migrate_on_boot = false;
    config.database.password = None;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_migrate_on_boot_true_with_a_bootstrap_password_configured() {
    let mut config = minimal_valid_config();
    config.database.migrate_on_boot = true;
    config.database.password = Some("bootstrap-pass".into());
    assert!(config.validate().is_ok());
}

// ── deployment_profile / validate_production_profile (P-production-safety-profile) ──

#[test]
fn validate_passes_with_deployment_profile_defaulted_to_development() {
    let config = minimal_valid_config();
    assert_eq!(config.app.deployment_profile, "development");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_an_unknown_deployment_profile() {
    let mut config = minimal_valid_config();
    config.app.deployment_profile = "staging".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("app.deployment_profile"));
}

/// Every field `validate_production_profile` requires, set to a
/// compliant value — the baseline the rejection tests below each flip
/// exactly one field away from, to prove that field (not some other
/// unrelated default) is what's rejecting.
fn production_ready_config() -> AppConfig {
    let mut config = minimal_valid_config();
    config.app.deployment_profile = "production".into();
    // BCF-3: the shipped-template denylist is production-only, and the
    // development fixture's `test-only-throwaway` secrets are exactly what it
    // refuses (BCF-D1 keeps that value valid in development). Give the
    // production baseline real-looking values so one flipped field below is
    // still what the rejection tests prove.
    config.auth.jwt_secret = KeyRing::single("production-jwt-secret-32-bytes-minimum-000".into());
    config.auth.apikey_hash_pepper = "production-apikey-pepper-32-bytes-minimum-0".into();
    config.database.ssl_mode = "verify-full".into();
    config.database.ssl_root_cert = Some("/etc/attome/pg-ca.pem".into());
    config.cache.tls_enabled = true;
    config.storage.s3_verify_ssl = true;
    config.storage.s3_endpoint = "https://s3.example.internal".into();
    config.auth.apikey_default_expiry_days = Some(90);
    config.audit.signing_enabled = true;
    config.audit.signing_key_id = "audit-key-1".into();
    // Exactly 64 hex characters — 32 bytes of Ed25519 seed (BCF-7).
    config.audit.signing_private_key =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into();
    config.audit.erasure_key_encryption_key = KeyRing::single("fe".repeat(32));
    config.database.migrate_on_boot = false;
    config.database.runtime = Some(RuntimeDbCredentials {
        user: "attome_runtime".into(),
        password: "throwaway-runtime-password".into(),
    });
    config.jobs.run_worker_inline = false;
    config
}

#[test]
fn validate_accepts_a_fully_hardened_production_profile() {
    assert!(production_ready_config().validate().is_ok());
}

#[test]
fn validate_accepts_a_production_profile_shaped_like_server_or_worker_with_no_bootstrap_password() {
    // P-bootstrap-credential-scoping (D-204) — the exact shape
    // docker-compose.yml's new config.runtime.json renders for
    // `server`/`worker`: production profile, migrate_on_boot already
    // required false by this fixture, and now also no
    // database.password at all. database.runtime being configured is
    // what makes this safe in practice — since B7 the fixture sets it
    // and validate() itself demands it (see
    // validate_rejects_production_profile_without_database_runtime
    // below); database.migrator stays boot.rs's own runtime gate, not a
    // validate()-time field. validate() only needs to not demand a
    // bootstrap credential this process was deliberately never given.
    let mut config = production_ready_config();
    config.database.password = None;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_profile_with_ssl_mode_not_verify_full() {
    let mut config = production_ready_config();
    config.database.ssl_mode = "prefer".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("database.ssl_mode"));
}

#[test]
fn validate_rejects_production_profile_with_cache_tls_disabled() {
    let mut config = production_ready_config();
    config.cache.tls_enabled = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("cache.tls_enabled"));
}

#[test]
fn validate_rejects_production_profile_with_coordination_role_tls_disabled() {
    let mut config = production_ready_config();
    config.cache.roles.coordination = Some(CacheRoleOverride {
        host: "coordination.internal".into(),
        port: 6379,
        password: String::new().into(),
        db: 0,
        connection_pool_size: 16,
        timeout: 2000,
        tls_enabled: false,
        tls_ca_path: None,
        sentinel: None,
    });
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("cache.roles.coordination.tls_enabled"));
}

#[test]
fn validate_rejects_production_profile_with_s3_verify_ssl_disabled() {
    let mut config = production_ready_config();
    config.storage.s3_verify_ssl = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("storage.s3_verify_ssl"));
}

/// D-501: `s3_verify_ssl = true` (already set on `production_ready_config`)
/// does not make an `http://` endpoint safe — the scheme decides the
/// transport.
#[test]
fn validate_rejects_production_profile_with_plain_http_storage_endpoint() {
    let mut config = production_ready_config();
    config.storage.s3_endpoint = "http://rustfs.internal:9000".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("storage.s3_endpoint"));
}

#[test]
fn validate_rejects_production_profile_with_plain_http_storage_public_endpoint() {
    let mut config = production_ready_config();
    config.storage.s3_public_endpoint = "http://files.internal".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("storage.s3_public_endpoint"));
}

/// BCF-18 (finding BCF-F18): a real-but-plain-http public frontend URL was
/// accepted, so reset/invitation links could go out over http.
#[test]
fn validate_rejects_production_profile_with_http_public_frontend_url() {
    let mut config = production_ready_config();
    config.app.public_frontend_url = Some("http://app.customer.com".into());
    let err = config.validate().unwrap_err();
    assert!(
        format!("{err}").contains("app.public_frontend_url"),
        "{err}"
    );
}

#[test]
fn validate_accepts_production_profile_with_https_public_frontend_url() {
    let mut config = production_ready_config();
    config.app.public_frontend_url = Some("https://app.customer.com".into());
    assert!(config.validate().is_ok());
}

/// BCF-18's rule is production-only: a local dev deployment's plain-http
/// frontend URL keeps working.
#[test]
fn validate_accepts_an_http_public_frontend_url_outside_production() {
    let mut config = minimal_valid_config();
    config.app.public_frontend_url = Some("http://localhost:4199".into());
    assert!(config.validate().is_ok());
}

/// An empty endpoint selects AWS S3 proper, which is always TLS.
#[test]
fn validate_accepts_production_profile_storage_against_aws_s3_proper() {
    let mut config = production_ready_config();
    config.storage.s3_endpoint = String::new();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_production_profile_with_https_storage_public_endpoint() {
    let mut config = production_ready_config();
    config.storage.s3_public_endpoint = "https://files.example.com".into();
    assert!(config.validate().is_ok());
}

/// The https rule is production-only; development keeps plain-http local
/// RustFS/MinIO working.
#[test]
fn validate_accepts_plain_http_storage_endpoints_outside_production() {
    let mut config = minimal_valid_config();
    config.storage.s3_endpoint = "http://localhost:9000".into();
    config.storage.s3_public_endpoint = "http://127.0.0.1:9000".into();
    assert_eq!(config.app.deployment_profile, "development");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_profile_with_a_non_https_cors_origin() {
    let mut config = production_ready_config();
    config.cors.allowed_origins = vec!["http://app.customer.com".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("cors.allowed_origins[0]"));
    assert!(format!("{err}").contains("https://"));
}

#[test]
fn validate_accepts_production_profile_with_an_https_cors_origin() {
    let mut config = production_ready_config();
    config.cors.allowed_origins = vec!["https://app.customer.com".into()];
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_profile_with_csrf_enforce_disabled() {
    let mut config = production_ready_config();
    config.security.csrf_enforce = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("security.csrf_enforce"));
}

#[test]
fn validate_rejects_production_profile_with_strict_privileged_authz_disabled() {
    let mut config = production_ready_config();
    config.security.strict_privileged_authz = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("security.strict_privileged_authz"));
}

/// BCF-4 (finding BCF-F6, criterion S2): every `security.*` bool that defaults
/// to `true` must be refused in production or carry a written exemption.
///
/// Structural half: the field list is parsed out of `sections/auth.rs` rather
/// than hand-maintained, so a new `#[serde(default = "default_true")]` bool
/// cannot land unaccounted for — it has no arm in `set_security_bool`, and the
/// test fails with the field's name instead of passing silently.
#[test]
fn every_security_kill_switch_is_production_gated() {
    /// Default-true security switches deliberately left ungated, each with the
    /// reason that leaving it ungated is safe. Empty today: all four
    /// default-`true` switches in `SecuritySection` are refused under
    /// `app.deployment_profile = "production"`. The list is the escape valve
    /// this test checks against, so a future ungated-by-design switch is a
    /// recorded decision rather than an oversight.
    const UNGATED_SECURITY_BOOLS: &[(&str, &str)] = &[];

    fn set_security_bool(config: &mut AppConfig, field: &str, value: bool) -> bool {
        match field {
            "csrf_enforce" => config.security.csrf_enforce = value,
            "strict_privileged_authz" => config.security.strict_privileged_authz = value,
            "strict_revocation" => config.security.strict_revocation = value,
            "csp_enforce" => config.security.csp_enforce = value,
            _ => return false,
        }
        true
    }

    let source = include_str!("sections/auth.rs");
    let body = source
        .split_once("pub struct SecuritySection {")
        .expect("SecuritySection must be declared in sections/auth.rs")
        .1;
    let body = body
        .split_once("\n}\n")
        .expect("SecuritySection's body must terminate")
        .0;

    let mut default_true: Vec<String> = Vec::new();
    let mut saw_default_true_attr = false;
    for line in body.lines() {
        let line = line.trim();
        if line.contains("default = \"default_true\"") {
            saw_default_true_attr = true;
            continue;
        }
        if line.starts_with("///") || line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        let (name, ty) = rest.split_once(':').expect("field has a type");
        if ty.trim() == "bool," {
            if saw_default_true_attr {
                default_true.push(name.trim().to_string());
            }
            saw_default_true_attr = false;
        }
    }
    assert!(
        default_true.len() >= 4,
        "expected to parse the four known default-true security switches, found {default_true:?}"
    );

    for field in &default_true {
        if let Some((_, reason)) = UNGATED_SECURITY_BOOLS
            .iter()
            .find(|(name, _)| name == field)
        {
            assert!(
                !reason.trim().is_empty(),
                "security.{field} needs a written exemption reason"
            );
            continue;
        }
        let mut config = production_ready_config();
        assert!(
            set_security_bool(&mut config, field, false),
            "new default-true security switch security.{field} is not accounted for — either \
             refuse it in validate_production_profile and add a set_security_bool arm, or list \
             it in UNGATED_SECURITY_BOOLS with a reason"
        );
        let err = config.validate().expect_err(&format!(
            "security.{field} = false must be refused in production"
        ));
        assert!(
            format!("{err}").contains(&format!("security.{field}")),
            "security.{field}: {err}"
        );
    }
}

#[test]
fn validate_rejects_production_profile_with_csp_enforce_disabled() {
    let mut config = production_ready_config();
    config.security.csp_enforce = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("security.csp_enforce"));
}

#[test]
fn validate_rejects_production_profile_with_hsts_disabled() {
    let mut config = production_ready_config();
    config.security.hsts_max_age_secs = 0;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("security.hsts_max_age_secs"));
}

#[test]
fn validate_rejects_production_profile_with_a_token_hsts_max_age() {
    // The failure mode this guards is not "operator turned HSTS off" but
    // "operator left a 60-second value behind from a rollout test," which
    // looks enabled in a config diff and protects essentially nothing.
    let mut config = production_ready_config();
    config.security.hsts_max_age_secs = 60;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("security.hsts_max_age_secs"));
}

#[test]
fn validate_accepts_production_profile_with_the_default_hsts_max_age() {
    let config = production_ready_config();
    assert_eq!(config.security.hsts_max_age_secs, 31_536_000);
    config
        .validate()
        .expect("default HSTS max-age must satisfy the production profile");
}

#[test]
fn validate_rejects_production_profile_with_strict_revocation_disabled() {
    let mut config = production_ready_config();
    config.security.strict_revocation = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("security.strict_revocation"));
}

#[test]
fn validate_rejects_production_profile_with_no_apikey_default_expiry() {
    let mut config = production_ready_config();
    config.auth.apikey_default_expiry_days = None;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.apikey_default_expiry_days"));
}

#[test]
fn validate_rejects_production_profile_with_public_registration_and_unverified_email() {
    let mut config = production_ready_config();
    config.email.enabled = true;
    config.auth.registration_mode = "public".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("auth.require_verified_email"));
}

#[test]
fn validate_accepts_production_profile_with_public_registration_and_verified_email_required() {
    let mut config = production_ready_config();
    config.email.enabled = true;
    config.auth.registration_mode = "public".into();
    config.auth.require_verified_email = true;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_profile_with_audit_signing_disabled() {
    let mut config = production_ready_config();
    config.audit.signing_enabled = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.signing_enabled"));
}

/// D-540 ruling 1, audit 10/10 plan item 2.7 — beside the D-316 check below.
#[test]
fn validate_rejects_production_profile_with_audit_encryption_disabled() {
    let mut config = production_ready_config();
    config.audit.erasure_enabled = Some(false);
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.erasure_enabled"), "{err}");
}

#[test]
fn validate_rejects_production_profile_without_an_audit_encryption_key() {
    let mut config = production_ready_config();
    config.audit.erasure_key_encryption_key = KeyRing::default();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.erasure_enabled"), "{err}");

    // An explicit `true` with no key fails too — on the key itself.
    config.audit.erasure_enabled = Some(true);
    let err = config.validate().unwrap_err();
    assert!(
        format!("{err}").contains("audit.erasure_key_encryption_key"),
        "{err}"
    );
}

#[test]
fn validate_rejects_production_profile_with_the_development_audit_encryption_key() {
    let mut config = production_ready_config();
    config.audit.erasure_key_encryption_key =
        KeyRing::single(crate::config::sections::audit::DEVELOPMENT_ERASURE_KEY.to_owned());
    let err = config.validate().unwrap_err();
    assert!(
        format!("{err}").contains("audit.erasure_key_encryption_key"),
        "{err}"
    );
}

#[test]
fn validate_accepts_production_profile_with_audit_encryption_on_explicitly() {
    let mut config = production_ready_config();
    config.audit.erasure_enabled = Some(true);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_profile_with_chainer_disabled() {
    let mut config = production_ready_config();
    config.audit.chainer_enabled = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.chainer_enabled"));
}

// ── audit.anchor_store / external anchoring immutability (D-352, TODO-004) ──

/// A compliant anchor store: its own bucket, its own credential, a real
/// Object Lock mode, a non-zero retention. Every rejection test below flips
/// exactly one field away from this.
fn compliant_anchor_store() -> AnchorStoreSection {
    AnchorStoreSection {
        s3_endpoint: "https://anchors.example.internal".into(),
        s3_region: "us-east-1".into(),
        s3_bucket: "attome-audit-anchors".into(),
        s3_access_key: "anchor-producer-key".into(),
        s3_secret_key: "anchor-producer-secret".into(),
        s3_verify_ssl: true,
        object_lock_mode: "compliance".into(),
        object_lock_retention_days: 3650,
    }
}

/// The baseline the anchoring tests build on: a hardened production config
/// with anchoring actually turned on and a compliant store behind it.
fn production_with_anchoring() -> AppConfig {
    let mut config = production_ready_config();
    config.audit.external_anchoring_enabled = true;
    config.audit.anchor_store = Some(compliant_anchor_store());
    config
}

#[test]
fn validate_accepts_production_anchoring_with_a_worm_anchor_store() {
    assert!(production_with_anchoring().validate().is_ok());
}

/// Anchoring off means no anchor store is needed — the gate must not fire on
/// a deployment that never opted in.
#[test]
fn validate_accepts_production_with_anchoring_disabled_and_no_anchor_store() {
    let config = production_ready_config();
    assert!(!config.audit.external_anchoring_enabled);
    assert!(config.audit.anchor_store.is_none());
    assert!(config.validate().is_ok());
}

/// The core of TODO-004/H-1: D-174's original posture — anchoring on, no
/// dedicated store, so anchors land in the general upload bucket under the
/// application's own delete-capable credential — must not boot in production.
#[test]
fn validate_rejects_production_anchoring_with_no_anchor_store() {
    let mut config = production_ready_config();
    config.audit.external_anchoring_enabled = true;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store"));
}

/// The same posture stays legal outside production — `cargo run` and the
/// test suites anchor to a single dev RustFS bucket.
#[test]
fn validate_accepts_development_anchoring_with_no_anchor_store() {
    let mut config = minimal_valid_config();
    config.audit.external_anchoring_enabled = true;
    assert_eq!(config.app.deployment_profile, "development");
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_anchoring_with_object_lock_mode_none() {
    let mut config = production_with_anchoring();
    config.audit.anchor_store.as_mut().unwrap().object_lock_mode = "none".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.object_lock_mode"));
}

#[test]
fn validate_accepts_production_anchoring_in_governance_mode() {
    let mut config = production_with_anchoring();
    config.audit.anchor_store.as_mut().unwrap().object_lock_mode = "governance".into();
    assert!(config.validate().is_ok());
}

/// A zero retention is an Object Lock configuration that locks nothing, and
/// it reads as "anchored" right up until someone needs the anchor.
#[test]
fn validate_rejects_production_anchoring_with_zero_retention() {
    let mut config = production_with_anchoring();
    config
        .audit
        .anchor_store
        .as_mut()
        .unwrap()
        .object_lock_retention_days = 0;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("object_lock_retention_days"));
}

#[test]
fn validate_rejects_production_anchoring_with_anchor_ssl_verification_disabled() {
    let mut config = production_with_anchoring();
    config.audit.anchor_store.as_mut().unwrap().s3_verify_ssl = false;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.s3_verify_ssl"));
}

#[test]
fn validate_rejects_production_anchoring_over_plain_http() {
    let mut config = production_with_anchoring();
    config.audit.anchor_store.as_mut().unwrap().s3_endpoint = "http://anchors.internal".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.s3_endpoint"));
}

/// An empty endpoint selects AWS S3 proper, which is always TLS — it must
/// not trip the `https://` check meant for a self-hosted endpoint.
#[test]
fn validate_accepts_production_anchoring_against_aws_s3_proper() {
    let mut config = production_with_anchoring();
    config.audit.anchor_store.as_mut().unwrap().s3_endpoint = String::new();
    assert!(config.validate().is_ok());
}

/// Reusing the upload credential defeats the identity-side control even when
/// the bucket really is separate and really is locked: that credential is
/// exactly what a deployment compromise yields.
#[test]
fn validate_rejects_production_anchoring_that_reuses_the_upload_credential() {
    let mut config = production_with_anchoring();
    let upload_key = config.storage.s3_access_key.clone();
    config.audit.anchor_store.as_mut().unwrap().s3_access_key = upload_key;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.s3_access_key"));
}

#[test]
fn validate_rejects_production_anchoring_with_a_missing_anchor_credential() {
    let mut config = production_with_anchoring();
    config.audit.anchor_store.as_mut().unwrap().s3_secret_key = String::new().into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.s3_access_key"));
}

/// Sharing the upload bucket is not a weaker configuration of anchoring, it
/// is the absence of it — that bucket's credential must keep `DeleteObject`
/// for quarantine cleanup and erasure, so it can never carry retention.
/// Rejected in EVERY profile, unlike the checks above.
#[test]
fn validate_rejects_an_anchor_store_sharing_the_upload_bucket_in_any_profile() {
    let mut config = minimal_valid_config();
    let mut anchor = compliant_anchor_store();
    anchor.s3_endpoint = config.storage.s3_endpoint.clone();
    anchor.s3_bucket = config.storage.s3_bucket.clone();
    config.audit.anchor_store = Some(anchor);
    assert_eq!(config.app.deployment_profile, "development");
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.s3_bucket"));
}

/// Same bucket NAME on a genuinely different endpoint is a different bucket.
#[test]
fn validate_accepts_an_anchor_bucket_named_like_the_upload_bucket_on_another_endpoint() {
    let mut config = minimal_valid_config();
    let mut anchor = compliant_anchor_store();
    anchor.s3_bucket = config.storage.s3_bucket.clone();
    assert_ne!(anchor.s3_endpoint, config.storage.s3_endpoint);
    config.audit.anchor_store = Some(anchor);
    assert!(config.validate().is_ok());
}

/// An unrecognized mode cannot be read as "probably fine" — the field
/// declares what was actually provisioned out-of-band.
#[test]
fn validate_rejects_an_unknown_object_lock_mode_in_any_profile() {
    let mut config = minimal_valid_config();
    let mut anchor = compliant_anchor_store();
    anchor.object_lock_mode = "worm".into();
    config.audit.anchor_store = Some(anchor);
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("audit.anchor_store.object_lock_mode"));
}

/// An omitted `audit.anchor_store` must stay `None` rather than
/// deserializing into an all-empty section that would then read as
/// "configured" to the production gate.
#[test]
fn an_omitted_anchor_store_deserializes_to_none() {
    let deserialized: AuditSection =
        serde_json::from_str("{}").expect("an empty audit section must deserialize");
    assert!(deserialized.anchor_store.is_none());
}

/// D-316 — the flip itself, asserted separately from the production-profile
/// rule above: a config that simply omits `audit.chainer_enabled` gets the
/// async chainer path, not the serialized sync append. `production_ready_config`
/// deliberately does not set this field, so the acceptance test above is only
/// meaningful while this one holds.
#[test]
fn audit_chainer_is_enabled_by_default() {
    let config = minimal_valid_config();
    assert!(
        config.audit.chainer_enabled,
        "an omitted audit.chainer_enabled must default to the async chainer path (D-316)"
    );
    let deserialized: AuditSection =
        serde_json::from_str("{}").expect("an empty audit section must deserialize");
    assert!(
        deserialized.chainer_enabled,
        "serde's default must agree with AuditSection::default() (D-316)"
    );
}

#[test]
fn validate_rejects_production_profile_with_migrate_on_boot_true() {
    let mut config = production_ready_config();
    config.database.migrate_on_boot = true;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("database.migrate_on_boot"));
}

/// B7 (technical due diligence 2026-08-24): the production profile itself,
/// not just boot.rs's `APP_ENV != "debug"` check, must refuse to run
/// request-time CRUD on the bootstrap identity. The message has to be
/// actionable on its own — it names the key, the role to create, and the
/// migration that creates it.
#[test]
fn validate_rejects_production_profile_without_database_runtime() {
    let mut config = production_ready_config();
    config.database.runtime = None;
    let err = config.validate().unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("database.runtime"), "got: {msg}");
    assert!(msg.contains("attome_runtime"), "got: {msg}");
    assert!(
        msg.contains("0042_migrator_runtime_roles.sql"),
        "got: {msg}"
    );
    assert!(msg.contains("schema-bootstrap identity"), "got: {msg}");
}

/// The same config with `database.runtime` set is the fixture every other
/// production test starts from, so this is the explicit positive half of
/// the B7 pair rather than something proven only by side effect.
#[test]
fn validate_accepts_production_profile_with_database_runtime_set() {
    let mut config = production_ready_config();
    config.database.runtime = Some(RuntimeDbCredentials {
        user: "attome_runtime".into(),
        password: "another-throwaway-runtime-password".into(),
    });
    assert!(config.validate().is_ok());
}

/// `database.runtime` is a production-profile requirement, not a
/// validate()-wide one — the development profile still tolerates its absence
/// (boot.rs's `APP_ENV=debug` warning path), or local dev would need the
/// role split just to start.
#[test]
fn validate_does_not_require_database_runtime_outside_the_production_profile() {
    let mut config = minimal_valid_config();
    assert_eq!(config.app.deployment_profile, "development");
    config.database.runtime = None;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_production_profile_with_run_worker_inline_true() {
    let mut config = production_ready_config();
    config.jobs.run_worker_inline = true;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("jobs.run_worker_inline"));
}

fn oidc_provider(client_secret: &str) -> OidcProviderConfig {
    OidcProviderConfig {
        display_name: "Test IdP".into(),
        issuer: "https://idp.example.com".into(),
        client_id: "client-123".into(),
        client_secret: client_secret.into(),
        scopes: default_oidc_scopes(),
        email_claim: default_oidc_email_claim(),
        require_email_verified_claim: false,
        mfa_acr_values: Vec::new(),
        trust_idp_mfa: true,
    }
}

#[test]
fn validate_accepts_a_well_formed_oidc_provider() {
    let mut config = minimal_valid_config();
    config.oidc.providers.insert(
        "entra".into(),
        oidc_provider("a-secret-that-is-at-least-32-bytes-long"),
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_a_short_oidc_client_secret() {
    let mut config = minimal_valid_config();
    config
        .oidc
        .providers
        .insert("entra".into(), oidc_provider("too-short"));
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("oidc.providers.entra.client_secret"));
}

#[test]
fn validate_rejects_an_unresolved_oidc_client_secret_placeholder() {
    let mut config = minimal_valid_config();
    config
        .oidc
        .providers
        .insert("entra".into(), oidc_provider("${ENTRA_CLIENT_SECRET}"));
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("unresolved"));
}

#[test]
fn validate_rejects_an_oidc_provider_key_with_a_url_unsafe_character() {
    let mut config = minimal_valid_config();
    config.oidc.providers.insert(
        "entra/evil".into(),
        oidc_provider("a-secret-that-is-at-least-32-bytes-long"),
    );
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("oidc.providers"));
}

#[test]
fn redis_url_uses_rediss_scheme_only_when_tls_enabled() {
    let mut config = minimal_valid_config();
    assert!(config.redis_url().starts_with("redis://"));
    config.cache.tls_enabled = true;
    assert!(config.redis_url().starts_with("rediss://"));
}

#[test]
fn resolved_placeholder_expands_and_reports_nothing() {
    // PATH is set in every test environment on every supported platform.
    let (out, unresolved) = expand_env_vars("prefix ${PATH} suffix");
    assert!(unresolved.is_empty(), "PATH must resolve: {unresolved:?}");
    assert!(
        !out.contains("${"),
        "no literal placeholder may remain: {out}"
    );
    assert!(out.starts_with("prefix ") && out.ends_with(" suffix"));
}

#[test]
fn unresolved_placeholder_is_left_literal_and_reported() {
    let (out, unresolved) = expand_env_vars("a ${ATTOME_TEST_DEFINITELY_UNSET_9F3B} b");
    assert_eq!(out, "a ${ATTOME_TEST_DEFINITELY_UNSET_9F3B} b");
    assert_eq!(unresolved, vec!["ATTOME_TEST_DEFINITELY_UNSET_9F3B"]);
}

#[test]
fn multiple_unresolved_placeholders_are_all_reported() {
    let (_, unresolved) = expand_env_vars("${ATTOME_TEST_UNSET_A_9F3B}${ATTOME_TEST_UNSET_B_9F3B}");
    assert_eq!(
        unresolved,
        vec!["ATTOME_TEST_UNSET_A_9F3B", "ATTOME_TEST_UNSET_B_9F3B"]
    );
}

#[test]
fn unterminated_placeholder_is_left_as_is() {
    let (out, unresolved) = expand_env_vars("tail ${UNTERMINATED");
    assert_eq!(out, "tail ${UNTERMINATED");
    assert!(unresolved.is_empty());
}

// ── `_FILE` fallback (P-container-hardening, D-186) ────────────────────────
// SAFETY: `std::env::set_var`/`remove_var` are unsafe in edition 2024 (racy
// under concurrent mutation from other threads) — each test below uses a
// unique var/file name and cleans up its own env var in the same test, same
// pattern as this module's other ATTOME_TEST_* placeholder tests.

#[test]
fn file_variant_is_used_when_the_plain_var_is_unset_and_the_file_is_readable() {
    let dir = std::env::temp_dir();
    let file_path = dir.join("attome_test_9f3b_file_variant_used.secret");
    std::fs::write(&file_path, "  file-secret-value\n").unwrap();
    let file_var = "ATTOME_TEST_FILE_VARIANT_USED_9F3B_FILE";
    // SAFETY: unique var name, cleaned up before returning.
    unsafe {
        std::env::set_var(file_var, &file_path);
    }

    let (out, unresolved) = expand_env_vars("prefix ${ATTOME_TEST_FILE_VARIANT_USED_9F3B} suffix");

    // SAFETY: same var set above, always cleaned up regardless of assertion outcome below.
    unsafe {
        std::env::remove_var(file_var);
    }
    std::fs::remove_file(&file_path).ok();

    assert!(unresolved.is_empty(), "unresolved: {unresolved:?}");
    assert_eq!(
        out, "prefix file-secret-value suffix",
        "trims file contents"
    );
}

#[test]
fn plain_var_wins_over_file_variant_when_both_are_set() {
    let dir = std::env::temp_dir();
    let file_path = dir.join("attome_test_9f3b_plain_wins.secret");
    std::fs::write(&file_path, "file-value").unwrap();
    let plain_var = "ATTOME_TEST_PLAIN_WINS_9F3B";
    let file_var = "ATTOME_TEST_PLAIN_WINS_9F3B_FILE";
    // SAFETY: unique var names, both cleaned up before returning.
    unsafe {
        std::env::set_var(plain_var, "plain-value");
        std::env::set_var(file_var, &file_path);
    }

    let (out, unresolved) = expand_env_vars("${ATTOME_TEST_PLAIN_WINS_9F3B}");

    // SAFETY: same vars set above, always cleaned up regardless of assertion outcome below.
    unsafe {
        std::env::remove_var(plain_var);
        std::env::remove_var(file_var);
    }
    std::fs::remove_file(&file_path).ok();

    assert!(unresolved.is_empty());
    assert_eq!(out, "plain-value");
}

#[test]
fn unreadable_file_variant_is_reported_unresolved_same_as_a_missing_var() {
    let file_var = "ATTOME_TEST_UNREADABLE_FILE_9F3B_FILE";
    // SAFETY: unique var name, cleaned up before returning. Points at a
    // path that is never created, so the read fails.
    unsafe {
        std::env::set_var(
            file_var,
            std::env::temp_dir().join("attome_test_9f3b_does_not_exist.secret"),
        );
    }

    let (out, unresolved) = expand_env_vars("${ATTOME_TEST_UNREADABLE_FILE_9F3B}");

    // SAFETY: same var set above, always cleaned up regardless of assertion outcome below.
    unsafe {
        std::env::remove_var(file_var);
    }

    assert_eq!(
        out, "${ATTOME_TEST_UNREADABLE_FILE_9F3B}",
        "literal left in place"
    );
    assert_eq!(unresolved, vec!["ATTOME_TEST_UNREADABLE_FILE_9F3B"]);
}

// ── config_file_path() / from_file() precedence and gating ────────────────
// `CONFIG_FILE`/`APP_ENV` are fixed, well-known names (not per-test-unique
// like this module's other `ATTOME_TEST_*` vars), so every test below is
// serialized behind this lock — same reasoning and pattern as
// `PRODUCTION_CONFIG_ENV_LOCK` further down this file. Where a test needs
// one of the two vars genuinely *absent* (not just cleared) rather than set
// to a controlled value, it relies on this repo's own `.env`/`.env.example`
// convention never setting `CONFIG_FILE` or `APP_ENV` there (`APP_ENV=debug`
// is documented as a shell-level env var set immediately before `cargo run`,
// per CLAUDE.md, not a `.env` entry) — true in CI, and true for a normal
// local checkout. `config_file_path()` calls `dotenvy::dotenv().ok()`, which
// never overrides an already-set var, so any test that sets both vars
// explicitly (rather than relying on absence) is immune to this regardless.
static CONFIG_FILE_PATH_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn config_file_path_prefers_explicit_config_file_env_var_over_app_env() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; both vars are
    // set to controlled values here, so ambient `.env` state cannot affect
    // this test (dotenvy never overrides an already-set var). Cleaned up
    // before returning, regardless of assertion outcome below.
    unsafe {
        std::env::set_var("CONFIG_FILE", "/explicit/path/config.json");
        std::env::set_var("APP_ENV", "debug");
    }

    let path = AppConfig::config_file_path();

    // SAFETY: same vars set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::remove_var("APP_ENV");
    }

    assert_eq!(
        path, "/explicit/path/config.json",
        "CONFIG_FILE must win regardless of APP_ENV"
    );
}

#[test]
fn config_file_path_defaults_to_debug_json_under_app_env_debug() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above. `CONFIG_FILE`'s
    // absence relies on this module's doc comment above; cleaned up before
    // returning regardless of outcome.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::set_var("APP_ENV", "debug");
    }

    let path = AppConfig::config_file_path();

    // SAFETY: same var set above.
    unsafe {
        std::env::remove_var("APP_ENV");
    }

    assert_eq!(path, "config.debug.json");
}

#[test]
fn config_file_path_defaults_to_config_json_otherwise() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above. `APP_ENV` is set
    // to a controlled non-"debug" sentinel (not removed) specifically so this
    // test does not depend on APP_ENV being absent from the ambient
    // environment — only `CONFIG_FILE`'s absence relies on this module's doc
    // comment above. Cleaned up before returning regardless of outcome.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::set_var("APP_ENV", "test-sentinel-not-debug");
    }

    let path = AppConfig::config_file_path();

    // SAFETY: same var set above.
    unsafe {
        std::env::remove_var("APP_ENV");
    }

    assert_eq!(path, "config.json");
}

#[test]
fn from_file_rejects_unresolved_placeholder_outside_debug() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = std::env::temp_dir().join("attome_test_cfp_9f3b_unresolved_non_debug.json");
    std::fs::write(&path, r#"{"x": "${ATTOME_TEST_CFP_9F3B_UNSET_1}"}"#).unwrap();

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; both vars set
    // to controlled values, cleaned up before returning regardless of
    // outcome. The unresolved-placeholder gate returns before this file's
    // content is ever deserialized into `AppConfig`, so it doesn't need to
    // be a valid config.
    unsafe {
        std::env::set_var("CONFIG_FILE", &path);
        std::env::set_var("APP_ENV", "test-sentinel-not-debug");
    }

    let result = AppConfig::from_file();

    // SAFETY: same vars set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::remove_var("APP_ENV");
    }
    std::fs::remove_file(&path).ok();

    assert!(
        matches!(result, Err(ConfigError::UnresolvedPlaceholders { .. })),
        "expected UnresolvedPlaceholders, got {result:?}"
    );
}

#[test]
fn from_file_tolerates_unresolved_placeholder_under_app_env_debug() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // A full, otherwise-valid config (same shape as `minimal_valid_config()`)
    // with one field's value replaced by an unresolved `${VAR}` — under
    // `APP_ENV=debug` the gate must tolerate it and leave the literal in
    // place rather than failing or silently blanking the field.
    let json = r#"{
        "app": {
            "port": 0, "frontend_host": "${ATTOME_TEST_CFP_9F3B_UNSET_2}", "frontend_port": 4200,
            "log_level": "error", "threads": 1, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
            "keepalive_requests": 100, "static_files_cache_time": 0
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
            "password": "test", "schema": "test", "connection_number": 1,
            "timeout": 5.0
        },
        "cache": {
            "host": "localhost", "port": 6379, "password": "", "db": 0,
            "connection_pool_size": 1, "timeout": 500
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
            "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
            "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
        },
        "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
        "observability": {
            "metrics_port": 0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "a@b.c",
            "smtp_from_name": "t", "smtp_use_tls": false
        },
        "google_ai": { "api_key": "test" }
    }"#;
    let path = std::env::temp_dir().join("attome_test_cfp_9f3b_unresolved_debug.json");
    std::fs::write(&path, json).unwrap();

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; both vars set
    // to controlled values, cleaned up before returning regardless of
    // outcome.
    unsafe {
        std::env::set_var("CONFIG_FILE", &path);
        std::env::set_var("APP_ENV", "debug");
    }

    let result = AppConfig::from_file();

    // SAFETY: same vars set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::remove_var("APP_ENV");
    }
    std::fs::remove_file(&path).ok();

    let config = result.expect("APP_ENV=debug must tolerate an unresolved placeholder");
    assert_eq!(
        config.app.frontend_host, "${ATTOME_TEST_CFP_9F3B_UNSET_2}",
        "the unresolved literal must be left in place, not blanked or substituted"
    );
}

#[test]
fn from_file_reports_not_a_file_when_the_resolved_path_is_a_directory() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = std::env::temp_dir().join("attome_test_cfp_9f3b_dir_not_file");
    std::fs::create_dir_all(&dir).unwrap();

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; cleaned up
    // before returning regardless of outcome.
    unsafe {
        std::env::set_var("CONFIG_FILE", &dir);
    }

    let result = AppConfig::from_file();

    // SAFETY: same var set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
    }
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        matches!(result, Err(ConfigError::NotAFile { .. })),
        "expected NotAFile, got {result:?}"
    );
}

#[test]
fn from_file_reports_file_not_found_when_the_resolved_path_is_missing() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = std::env::temp_dir().join("attome_test_cfp_9f3b_does_not_exist.json");
    std::fs::remove_file(&path).ok(); // guard against a leftover from a prior failed run

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; cleaned up
    // before returning regardless of outcome.
    unsafe {
        std::env::set_var("CONFIG_FILE", &path);
    }

    let result = AppConfig::from_file();

    // SAFETY: same var set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
    }

    assert!(
        matches!(result, Err(ConfigError::FileNotFound { .. })),
        "expected FileNotFound, got {result:?}"
    );
}

// ── Secret redaction regression guard ──────────────────────────────────────
// Every secret-bearing section already hand-rolls its own `Debug` impl (see
// each type's doc comment for why). This is not a new mechanism — it is a
// regression guard: a future field added to one of these sections without
// updating its `Debug` impl would otherwise leak silently, with nothing to
// catch it.
#[test]
fn debug_output_never_leaks_a_secret_value() {
    let mut config = minimal_valid_config();

    config.auth.jwt_secret = KeyRing::single("MARKER-JWT-SECRET".into());
    config.auth.oauth_google_client_secret = "MARKER-OAUTH-GOOGLE-CLIENT-SECRET".into();
    config.auth.apikey_hash_pepper = "MARKER-APIKEY-HASH-PEPPER".into();
    config.auth.mfa_encryption_key = KeyRing::single("MARKER-MFA-ENCRYPTION-KEY".into());
    config.auth.apikey_hash_previous_peppers = vec![ApiKeyPepper {
        id: 1,
        secret: "MARKER-PREVIOUS-PEPPER".into(),
    }];
    config.database.password = Some("MARKER-DB-PASSWORD".into());
    config.database.direct_url = Some("postgres://x:MARKER-DIRECT-URL@host/db".into());
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "ro".into(),
        password: "MARKER-RO-PASSWORD".into(),
        host: None,
        port: None,
    });
    config.database.migrator = Some(MigratorDbCredentials {
        user: "mig".into(),
        password: "MARKER-MIGRATOR-PASSWORD".into(),
    });
    config.database.runtime = Some(RuntimeDbCredentials {
        user: "rt".into(),
        password: "MARKER-RUNTIME-PASSWORD".into(),
    });
    config.cache.password = "MARKER-CACHE-PASSWORD".into();
    config.cache.sentinel = Some(CacheSentinelConfig {
        service_name: "m".into(),
        nodes: vec![],
        sentinel_username: None,
        sentinel_password: Some("MARKER-SENTINEL-PASSWORD".into()),
    });
    config.cache.roles.coordination = Some(CacheRoleOverride {
        host: "h".into(),
        port: 1,
        password: "MARKER-COORD-PASSWORD".into(),
        db: 0,
        connection_pool_size: 1,
        timeout: 1,
        tls_enabled: false,
        tls_ca_path: None,
        sentinel: None,
    });
    config.storage.s3_access_key = "MARKER-S3-ACCESS-KEY".into();
    config.storage.s3_secret_key = "MARKER-S3-SECRET-KEY".into();
    config.email.smtp_password = "MARKER-SMTP-PASSWORD".into();
    config.google_ai.api_key = "MARKER-GOOGLE-AI-API-KEY".into();
    config.s2s.key_encryption_key = KeyRing::single("MARKER-S2S-KEY".into());
    config.audit.signing_private_key = "MARKER-SIGNING-PRIVATE-KEY".into();
    config.audit.erasure_key_encryption_key = KeyRing::single("MARKER-ERASURE-KEY".into());
    config.audit.anchor_store = Some(AnchorStoreSection {
        s3_endpoint: "e".into(),
        s3_region: "r".into(),
        s3_bucket: "b".into(),
        s3_access_key: "MARKER-ANCHOR-ACCESS-KEY".into(),
        s3_secret_key: "MARKER-ANCHOR-SECRET-KEY".into(),
        s3_verify_ssl: true,
        object_lock_mode: "none".into(),
        object_lock_retention_days: 0,
    });
    config.events.webhook_signing_key = KeyRing::single("MARKER-WEBHOOK-KEY".into());
    config.integration.credential_encryption_key = KeyRing::single("MARKER-INTEGRATION-KEY".into());
    config.oidc.providers.insert(
        "test".into(),
        OidcProviderConfig {
            display_name: "T".into(),
            issuer: "https://example.test".into(),
            client_id: "cid".into(),
            client_secret: "MARKER-OIDC-CLIENT-SECRET".into(),
            scopes: default_oidc_scopes(),
            email_claim: default_oidc_email_claim(),
            require_email_verified_claim: true,
            mfa_acr_values: Vec::new(),
            trust_idp_mfa: true,
        },
    );

    let debug_output = format!("{config:?}");

    let markers = [
        "MARKER-JWT-SECRET",
        "MARKER-OAUTH-GOOGLE-CLIENT-SECRET",
        "MARKER-APIKEY-HASH-PEPPER",
        "MARKER-MFA-ENCRYPTION-KEY",
        "MARKER-PREVIOUS-PEPPER",
        "MARKER-DB-PASSWORD",
        "MARKER-DIRECT-URL",
        "MARKER-RO-PASSWORD",
        "MARKER-MIGRATOR-PASSWORD",
        "MARKER-RUNTIME-PASSWORD",
        "MARKER-CACHE-PASSWORD",
        "MARKER-SENTINEL-PASSWORD",
        "MARKER-COORD-PASSWORD",
        "MARKER-S3-ACCESS-KEY",
        "MARKER-S3-SECRET-KEY",
        "MARKER-SMTP-PASSWORD",
        "MARKER-GOOGLE-AI-API-KEY",
        "MARKER-S2S-KEY",
        "MARKER-SIGNING-PRIVATE-KEY",
        "MARKER-ERASURE-KEY",
        "MARKER-ANCHOR-ACCESS-KEY",
        "MARKER-ANCHOR-SECRET-KEY",
        "MARKER-WEBHOOK-KEY",
        "MARKER-INTEGRATION-KEY",
        "MARKER-OIDC-CLIENT-SECRET",
    ];
    for marker in markers {
        assert!(
            !debug_output.contains(marker),
            "AppConfig's Debug output leaked a secret value: {marker}"
        );
    }
    assert!(
        debug_output.contains("[REDACTED]"),
        "expected at least one [REDACTED] marker in AppConfig's Debug output"
    );
}

/// BCF-1 (finding BCF-F3, criterion S8): redaction is structural, not a
/// hand-maintained marker list. Every `pub` field whose name looks like a
/// secret and whose type can hold one must live on a struct with its own
/// hand-written `impl std::fmt::Debug` — the derived one prints the raw value.
///
/// The struct/field inventory is parsed out of the section sources, so a new
/// secret field on a derived-`Debug` struct fails here the moment it is added.
#[test]
fn secret_named_fields_live_in_redacting_types() {
    /// `(label, source)` for every file that declares a config struct.
    const SOURCES: &[(&str, &str)] = &[
        ("sections/audit.rs", include_str!("sections/audit.rs")),
        ("sections/auth.rs", include_str!("sections/auth.rs")),
        ("sections/cache.rs", include_str!("sections/cache.rs")),
        (
            "sections/deployment.rs",
            include_str!("sections/deployment.rs"),
        ),
        ("sections/events.rs", include_str!("sections/events.rs")),
        (
            "sections/inference.rs",
            include_str!("sections/inference.rs"),
        ),
        (
            "sections/integration.rs",
            include_str!("sections/integration.rs"),
        ),
        (
            "sections/observability.rs",
            include_str!("sections/observability.rs"),
        ),
        ("sections/portal.rs", include_str!("sections/portal.rs")),
        ("sections/storage.rs", include_str!("sections/storage.rs")),
        ("sections/webchat.rs", include_str!("sections/webchat.rs")),
        ("keyring.rs", include_str!("../keyring.rs")),
    ];

    /// `(struct name, secret field name, redacts itself)` for each sensitive
    /// field; a `Secret` field redacts itself (Z1-T2).
    fn secret_fields(source: &str) -> Vec<(String, String, bool)> {
        let mut found = Vec::new();
        let mut current: Option<String> = None;
        let mut depth = 0i32;
        for raw in source.lines() {
            let line = raw.trim();
            if line.starts_with("///") || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("pub struct ") {
                let name = rest
                    .split(['{', '<', ' '])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                depth = i32::from(line.contains('{'));
                current = Some(name);
                continue;
            }
            let Some(struct_name) = &current else {
                continue;
            };
            if line.starts_with('}') {
                depth -= 1;
                if depth <= 0 {
                    current = None;
                }
                continue;
            }
            if depth == 1
                && let Some(field) = line.strip_prefix("pub ")
                && let Some((field_name, field_type)) = field.split_once(':')
            {
                let field_name = field_name.trim();
                let field_type = field_type.trim().trim_end_matches(',');
                let secret_name = field_name.contains("secret")
                    || field_name.contains("password")
                    || field_name.contains("api_key")
                    || field_name.contains("private_key")
                    || field_name.ends_with("_key")
                    || field_name.contains("pepper");
                // A *public* key is not secret material: a bundle signer's
                // public key is meant to be printed and copied.
                let secret_name = secret_name && !field_name.contains("public_key");
                let self_redacting = field_type.contains("Secret");
                let sensitive_type = field_type.contains("String")
                    || field_type.contains("KeyRing")
                    || field_type.contains("str")
                    || self_redacting;
                if secret_name && sensitive_type {
                    found.push((struct_name.clone(), field_name.to_string(), self_redacting));
                }
            }
        }
        found
    }

    let mut unredacted: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for (label, source) in SOURCES {
        for (struct_name, field_name, self_redacting) in secret_fields(source) {
            checked += 1;
            if !self_redacting
                && !source.contains(&format!("impl std::fmt::Debug for {struct_name}"))
            {
                unredacted.push(format!("{label}: {struct_name}.{field_name}"));
            }
        }
    }
    assert!(
        checked >= 15,
        "the parser found only {checked} secret-shaped fields — it has drifted from the sources"
    );
    assert!(
        unredacted.is_empty(),
        "these secret-shaped fields live on structs with a derived Debug, which prints the raw \
         value; add a hand-written redacting `impl std::fmt::Debug` for each struct:\n  {}",
        unredacted.join("\n  ")
    );
}

// ── database_url / direct_database_url / readonly_database_url ────────────

#[test]
fn database_url_omits_the_colon_separator_when_password_is_empty() {
    let mut config = minimal_valid_config();
    config.database.password = Some(String::new().into());
    let url = config.database_url();
    assert!(
        url.starts_with("postgres://test@localhost:5555/test"),
        "got: {url}"
    );
}

#[test]
fn database_url_omits_the_colon_separator_when_password_is_none() {
    // P-bootstrap-credential-scoping (D-204): a process this credential
    // was deliberately never handed (server/worker in production, D-148)
    // must behave identically to the pre-existing empty-string case, not
    // panic/error — every legitimate caller of this URL is already
    // fail-closed gated before it can be reached (see `password`'s own
    // doc comment).
    let mut config = minimal_valid_config();
    config.database.password = None;
    let url = config.database_url();
    assert!(
        url.starts_with("postgres://test@localhost:5555/test"),
        "got: {url}"
    );
}

#[test]
fn database_url_url_encodes_user_and_password() {
    let mut config = minimal_valid_config();
    config.database.user = "weird user@x".into();
    config.database.password = Some("p@ss:word/!".into());
    let url = config.database_url();
    assert!(!url.contains("weird user@x"), "user must be encoded: {url}");
    assert!(
        !url.contains("p@ss:word/!"),
        "password must be encoded: {url}"
    );
    assert!(url.contains("weird%20user%40x"), "got: {url}");
}

#[test]
fn database_url_appends_the_search_path_option_with_the_configured_schema() {
    let mut config = minimal_valid_config();
    config.database.schema = "attome_dev".into();
    let url = config.database_url();
    assert!(
        url.ends_with("?options=-c%20search_path%3Dattome_dev%2Cpublic"),
        "got: {url}"
    );
}

#[test]
fn direct_database_url_falls_back_to_database_url_when_unset() {
    let config = minimal_valid_config();
    assert_eq!(config.direct_database_url(), config.database_url());
}

#[test]
fn direct_database_url_uses_the_configured_direct_url_when_set() {
    let mut config = minimal_valid_config();
    config.database.direct_url = Some("postgres://pgbouncer-direct/whatever".into());
    assert_eq!(
        config.direct_database_url(),
        "postgres://pgbouncer-direct/whatever"
    );
}

#[test]
fn readonly_database_url_is_none_when_database_readonly_is_unconfigured() {
    let config = minimal_valid_config();
    assert!(config.readonly_database_url().is_none());
}

#[test]
fn readonly_database_url_uses_the_readonly_role_credentials_and_the_primary_host() {
    let mut config = minimal_valid_config();
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "ro_user".into(),
        password: "ro_pass".into(),
        host: None,
        port: None,
    });
    let url = config
        .readonly_database_url()
        .expect("readonly credentials were configured");
    assert!(
        url.starts_with("postgres://ro_user:ro_pass@localhost:5555/test"),
        "got: {url}"
    );
}

#[test]
fn readonly_database_url_uses_its_own_host_and_port_when_set() {
    // D-155 — closes D-125's known gap: the readonly pool can now point
    // at a distinct endpoint (e.g. a Patroni HAProxy replica listener)
    // instead of always sharing the primary's database.host/.port.
    let mut config = minimal_valid_config();
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "ro_user".into(),
        password: "ro_pass".into(),
        host: Some("haproxy".into()),
        port: Some(5433),
    });
    let url = config
        .readonly_database_url()
        .expect("readonly credentials were configured");
    assert!(
        url.starts_with("postgres://ro_user:ro_pass@haproxy:5433/test"),
        "got: {url}"
    );
}

#[test]
fn readonly_database_url_falls_back_to_primary_port_when_only_host_is_overridden() {
    // Partial override (host set, port not) — port must fall back to
    // database.port, not silently become 0/unset.
    let mut config = minimal_valid_config();
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "ro_user".into(),
        password: "ro_pass".into(),
        host: Some("haproxy".into()),
        port: None,
    });
    let url = config
        .readonly_database_url()
        .expect("readonly credentials were configured");
    assert!(
        url.starts_with("postgres://ro_user:ro_pass@haproxy:5555/test"),
        "got: {url}"
    );
}

// ── readonly_primary_database_url (P-api-consistency-hardening) ───────────

#[test]
fn readonly_primary_database_url_is_none_when_database_readonly_is_unconfigured() {
    let config = minimal_valid_config();
    assert!(config.readonly_primary_database_url().is_none());
}

#[test]
fn readonly_primary_database_url_uses_the_readonly_role_credentials_and_the_primary_host() {
    let mut config = minimal_valid_config();
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "ro_user".into(),
        password: "ro_pass".into(),
        host: None,
        port: None,
    });
    let url = config
        .readonly_primary_database_url()
        .expect("readonly credentials were configured");
    assert!(
        url.starts_with("postgres://ro_user:ro_pass@localhost:5555/test"),
        "got: {url}"
    );
}

#[test]
fn readonly_primary_database_url_ignores_the_readonly_role_own_host_and_port_override() {
    // The whole point of this method vs. readonly_database_url(): even
    // when D-155's override points the ordinary replica pool elsewhere
    // (a Patroni HAProxy replica listener, etc.), the primary-pointed
    // pool must still land on database.host/.port so a pinned caller
    // actually reads fresh data instead of a possibly-lagging replica.
    let mut config = minimal_valid_config();
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "ro_user".into(),
        password: "ro_pass".into(),
        host: Some("haproxy".into()),
        port: Some(5433),
    });
    let url = config
        .readonly_primary_database_url()
        .expect("readonly credentials were configured");
    assert!(
        url.starts_with("postgres://ro_user:ro_pass@localhost:5555/test"),
        "got: {url}"
    );
}

// ── migrator_database_url / direct_database_url interaction (D-117) ───────

#[test]
fn migrator_database_url_falls_back_to_database_url_when_unconfigured() {
    let config = minimal_valid_config();
    assert_eq!(config.migrator_database_url(), config.database_url());
}

#[test]
fn migrator_database_url_uses_the_migrator_role_credentials_and_the_primary_host() {
    let mut config = minimal_valid_config();
    config.database.migrator = Some(MigratorDbCredentials {
        user: "migrator_user".into(),
        password: "migrator_pass".into(),
    });
    let url = config.migrator_database_url();
    assert!(
        url.starts_with("postgres://migrator_user:migrator_pass@localhost:5555/test"),
        "got: {url}"
    );
}

#[test]
fn runtime_database_url_falls_back_to_database_url_when_unconfigured() {
    let config = minimal_valid_config();
    assert_eq!(config.runtime_database_url(), config.database_url());
}

#[test]
fn runtime_database_url_uses_the_runtime_role_credentials_and_the_primary_host() {
    let mut config = minimal_valid_config();
    config.database.runtime = Some(RuntimeDbCredentials {
        user: "runtime_user".into(),
        password: "runtime_pass".into(),
    });
    let url = config.runtime_database_url();
    assert!(
        url.starts_with("postgres://runtime_user:runtime_pass@localhost:5555/test"),
        "got: {url}"
    );
}

#[test]
fn direct_database_url_ignores_migrator_credentials_even_when_configured() {
    // D-117: direct_database_url() is the schema-bootstrap/migration pool
    // (and where 0042_migrator_runtime_roles.sql itself runs) — it must
    // stay on database.user, never attome_migrator, or the very seed
    // step that grants attome_migrator a login password could never run
    // (chicken-and-egg). See migrator_database_url's own doc comment.
    let mut config = minimal_valid_config();
    config.database.migrator = Some(MigratorDbCredentials {
        user: "migrator_user".into(),
        password: "migrator_pass".into(),
    });
    assert_eq!(config.direct_database_url(), config.database_url());
}

// ── allowed_origins / frontend_url ──────────────────────────────────────────

#[test]
fn allowed_origins_derives_a_dev_only_http_origin_when_cors_is_unconfigured() {
    let config = minimal_valid_config();
    assert_eq!(
        config.allowed_origins(),
        vec!["http://localhost:4200".to_string()]
    );
}

#[test]
fn allowed_origins_uses_the_explicit_cors_allow_list_when_configured() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://app.example.com".into()];
    assert_eq!(
        config.allowed_origins(),
        vec!["https://app.example.com".to_string()]
    );
}

#[test]
fn validate_accepts_a_well_formed_http_cors_origin_in_development() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["http://localhost:4200".into()];
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_a_cors_origin_with_no_explicit_port() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://app.example.com".into()];
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_a_cors_origin_that_is_an_ipv6_literal() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["http://[::1]:4200".into()];
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_a_wildcard_cors_origin() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["*".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("cors.allowed_origins[0]"));
    assert!(format!("{err}").contains("wildcard"));
}

#[test]
fn validate_rejects_a_cors_origin_missing_a_scheme() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["app.example.com".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("cors.allowed_origins[0]"));
}

#[test]
fn validate_rejects_a_cors_origin_with_an_unsupported_scheme() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["ftp://app.example.com".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("scheme"));
}

#[test]
fn validate_rejects_a_cors_origin_with_a_path_component() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://app.example.com/callback".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("cors.allowed_origins[0]"));
}

#[test]
fn validate_rejects_a_cors_origin_with_a_query_string() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://app.example.com?x=1".into()];
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_a_cors_origin_with_embedded_credentials() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://user:pass@app.example.com".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("credentials"));
}

#[test]
fn validate_rejects_a_cors_origin_with_an_empty_host() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://".into()];
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_a_cors_origin_with_a_non_numeric_port() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["https://app.example.com:abc".into()];
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("port"));
}

#[test]
fn validate_rejects_an_unterminated_ipv6_cors_origin() {
    let mut config = minimal_valid_config();
    config.cors.allowed_origins = vec!["http://[::1:4200".into()];
    assert!(config.validate().is_err());
}

#[test]
fn frontend_url_falls_back_to_the_derived_dev_origin_when_public_frontend_url_is_unset() {
    let config = minimal_valid_config();
    assert_eq!(config.frontend_url(), "http://localhost:4200");
}

#[test]
fn frontend_url_uses_public_frontend_url_when_configured() {
    let mut config = minimal_valid_config();
    config.app.public_frontend_url = Some("https://app.customer.com".into());
    assert_eq!(config.frontend_url(), "https://app.customer.com");
}

// ── token TTL conversions / bind_addr / request_timeout ─────────────────────

#[test]
fn access_token_expiry_secs_converts_configured_minutes_to_seconds() {
    let mut config = minimal_valid_config();
    config.auth.access_token_expiry_mins = 15;
    assert_eq!(config.access_token_expiry_secs(), 900);
}

#[test]
fn refresh_token_expiry_secs_converts_configured_days_to_seconds() {
    let mut config = minimal_valid_config();
    config.auth.refresh_token_expiry_days = 30;
    assert_eq!(config.refresh_token_expiry_secs(), 30 * 86_400);
}

#[test]
fn refresh_absolute_lifetime_secs_converts_configured_days_to_exact_seconds() {
    let mut config = minimal_valid_config();
    config.auth.refresh_absolute_lifetime_days = 30;
    assert_eq!(config.refresh_absolute_lifetime_secs(), 30 * 86_400);
}

#[test]
fn bind_addr_combines_server_host_and_port() {
    let mut config = minimal_valid_config();
    config.app.server_host = "0.0.0.0".into();
    config.app.port = 7865;
    assert_eq!(config.bind_addr(), "0.0.0.0:7865");
}

#[test]
fn request_timeout_converts_configured_seconds_into_a_duration() {
    let mut config = minimal_valid_config();
    config.app.request_timeout_secs = 30;
    assert_eq!(config.request_timeout(), std::time::Duration::from_secs(30));
}

// ── Redis role overrides (P1.15) ─────────────────────────────────────────────

fn role_override() -> CacheRoleOverride {
    CacheRoleOverride {
        host: "coordination.internal".into(),
        port: 6380,
        password: "role-pass".into(),
        db: 2,
        connection_pool_size: 32,
        timeout: 1000,
        tls_enabled: false,
        tls_ca_path: Some("/etc/attome/coordination-ca.pem".into()),
        sentinel: None,
    }
}

#[test]
fn cache_role_override_is_none_when_no_role_override_is_configured() {
    let config = minimal_valid_config();
    assert!(
        config
            .cache_role_override(CacheRole::Coordination)
            .is_none()
    );
}

#[test]
fn redis_url_for_role_falls_back_to_the_base_block_when_no_override_is_configured() {
    let config = minimal_valid_config();
    assert_eq!(
        config.redis_url_for_role(CacheRole::Coordination),
        config.redis_url()
    );
}

#[test]
fn redis_url_for_role_uses_the_role_override_when_configured() {
    let mut config = minimal_valid_config();
    config.cache.roles.coordination = Some(role_override());
    let url = config.redis_url_for_role(CacheRole::Coordination);
    assert_eq!(url, "redis://:role-pass@coordination.internal:6380/2");
    assert_ne!(url, config.redis_url());
}

#[test]
fn redis_pool_size_for_role_falls_back_to_the_base_pool_size_when_no_override() {
    let mut config = minimal_valid_config();
    config.cache.connection_pool_size = 7;
    assert_eq!(config.redis_pool_size_for_role(CacheRole::Coordination), 7);
}

#[test]
fn redis_pool_size_for_role_uses_the_role_overrides_pool_size_when_configured() {
    let mut config = minimal_valid_config();
    config.cache.roles.coordination = Some(role_override());
    assert_eq!(config.redis_pool_size_for_role(CacheRole::Coordination), 32);
}

#[test]
fn redis_timeout_ms_for_role_falls_back_to_the_base_timeout_when_no_override() {
    let mut config = minimal_valid_config();
    config.cache.timeout = 500;
    assert_eq!(
        config.redis_timeout_ms_for_role(CacheRole::Coordination),
        500
    );
}

#[test]
fn redis_timeout_ms_for_role_uses_the_role_overrides_timeout_when_configured() {
    let mut config = minimal_valid_config();
    config.cache.roles.coordination = Some(role_override());
    assert_eq!(
        config.redis_timeout_ms_for_role(CacheRole::Coordination),
        1000
    );
}

// ── BCA-14: cache.timeout = 0 is a boot error, on every block ───────────────

/// fred reads a zero command timeout as "no timeout", which removes the only
/// bound on a readiness `PING` and on every other Redis call (BSV-F07). The
/// base block is refused before any pool is built (D-038).
#[test]
fn validate_refuses_a_zero_base_cache_timeout() {
    let mut config = minimal_valid_config();
    config.cache.timeout = 0;
    let err = config
        .validate()
        .expect_err("cache.timeout = 0 must fail boot");
    assert!(format!("{err}").contains("cache.timeout"), "{err}");
}

/// BCA-14/BCA-F3: a role override is a fully separate endpoint with its own
/// timeout, so it gets its own refusal — and the message names that key, not
/// the base block an operator would otherwise go and change.
#[test]
fn validate_refuses_a_zero_coordination_role_cache_timeout() {
    let mut config = minimal_valid_config();
    let mut role = role_override();
    role.timeout = 0;
    config.cache.roles.coordination = Some(role);
    let err = config
        .validate()
        .expect_err("a coordination role timeout of 0 must fail boot");
    let err = format!("{err}");
    assert!(err.contains("cache.roles.coordination.timeout"), "{err}");
    assert!(
        !err.contains(r#""cache.timeout""#),
        "the refusal must name the role override key, not the base block: {err}"
    );
}

/// The documented default (2000) and a tuned role override (1000) both stay
/// legal — the refusal is exactly about zero.
#[test]
fn validate_accepts_a_positive_cache_timeout_on_both_blocks() {
    let mut config = minimal_valid_config();
    config.cache.timeout = 2000;
    config.cache.roles.coordination = Some(role_override());
    config
        .validate()
        .expect("positive cache timeouts must be accepted");
}

#[test]
fn redis_tls_ca_path_for_role_falls_back_to_the_base_blocks_path_when_no_override() {
    let mut config = minimal_valid_config();
    config.cache.tls_ca_path = Some("/etc/attome/base-ca.pem".into());
    assert_eq!(
        config.redis_tls_ca_path_for_role(CacheRole::Coordination),
        Some("/etc/attome/base-ca.pem".to_string())
    );
}

#[test]
fn redis_tls_ca_path_for_role_never_falls_back_to_the_base_blocks_path_when_an_override_is_configured()
 {
    // The role override is a fully separate endpoint (see the field doc on
    // redis_tls_ca_path_for_role) — its own tls_ca_path (None here) must
    // win even though the base block has one configured, never silently
    // borrow the base block's CA for a different endpoint.
    let mut config = minimal_valid_config();
    config.cache.tls_ca_path = Some("/etc/attome/base-ca.pem".into());
    let mut overridden = role_override();
    overridden.tls_ca_path = None;
    config.cache.roles.coordination = Some(overridden);
    assert_eq!(
        config.redis_tls_ca_path_for_role(CacheRole::Coordination),
        None
    );
}

// ── Redis Sentinel mode (P-redis-sentinel-config) ───────────────────────────

fn sentinel_config() -> CacheSentinelConfig {
    CacheSentinelConfig {
        service_name: "mymaster".into(),
        nodes: vec![
            CacheSentinelNode {
                host: "sentinel2.internal".into(),
                port: 26379,
            },
            CacheSentinelNode {
                host: "sentinel3.internal".into(),
                port: 26379,
            },
        ],
        sentinel_username: None,
        sentinel_password: None,
    }
}

#[test]
fn redis_url_uses_the_sentinel_scheme_and_query_params_when_sentinel_is_configured() {
    let mut config = minimal_valid_config();
    config.cache.host = "sentinel1.internal".into();
    config.cache.port = 26379;
    config.cache.sentinel = Some(sentinel_config());
    assert_eq!(
        config.redis_url(),
        "redis-sentinel://sentinel1.internal:26379/0?sentinelServiceName=mymaster\
         &node=sentinel2.internal:26379&node=sentinel3.internal:26379"
    );
}

#[test]
fn redis_url_sentinel_mode_uses_the_rediss_sentinel_scheme_when_tls_enabled() {
    let mut config = minimal_valid_config();
    config.cache.tls_enabled = true;
    config.cache.sentinel = Some(sentinel_config());
    assert!(config.redis_url().starts_with("rediss-sentinel://"));
}

#[test]
fn redis_url_sentinel_mode_carries_the_base_blocks_password_as_the_master_auth() {
    let mut config = minimal_valid_config();
    config.cache.password = "master-pass".into();
    config.cache.sentinel = Some(sentinel_config());
    assert!(
        config
            .redis_url()
            .starts_with("redis-sentinel://:master-pass@")
    );
}

#[test]
fn redis_url_sentinel_mode_percent_encodes_the_service_name_and_sentinel_credentials() {
    let mut config = minimal_valid_config();
    let mut sentinel = sentinel_config();
    sentinel.service_name = "my master".into();
    sentinel.sentinel_username = Some("sentinel-user".into());
    sentinel.sentinel_password = Some("p@ss&word".into());
    config.cache.sentinel = Some(sentinel);
    let url = config.redis_url();
    assert!(
        url.contains("sentinelServiceName=my%20master"),
        "got: {url}"
    );
    assert!(url.contains("sentinelUsername=sentinel-user"), "got: {url}");
    assert!(url.contains("sentinelPassword=p%40ss%26word"), "got: {url}");
}

#[test]
fn redis_url_for_role_uses_sentinel_mode_when_the_role_override_configures_it() {
    let mut config = minimal_valid_config();
    let mut overridden = role_override();
    overridden.sentinel = Some(sentinel_config());
    config.cache.roles.coordination = Some(overridden);
    let url = config.redis_url_for_role(CacheRole::Coordination);
    assert_eq!(
        url,
        "redis-sentinel://:role-pass@coordination.internal:6380/2?sentinelServiceName=mymaster\
         &node=sentinel2.internal:26379&node=sentinel3.internal:26379"
    );
}

#[test]
fn validate_accepts_a_well_formed_sentinel_config() {
    let mut config = minimal_valid_config();
    config.cache.sentinel = Some(sentinel_config());
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_sentinel_with_an_empty_service_name() {
    let mut config = minimal_valid_config();
    let mut sentinel = sentinel_config();
    sentinel.service_name = "  ".into();
    config.cache.sentinel = Some(sentinel);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::Invalid { field, .. }) if field == "cache.sentinel.service_name"
    ));
}

#[test]
fn validate_rejects_a_sentinel_node_with_an_empty_host() {
    let mut config = minimal_valid_config();
    let mut sentinel = sentinel_config();
    sentinel.nodes.push(CacheSentinelNode {
        host: String::new(),
        port: 26379,
    });
    config.cache.sentinel = Some(sentinel);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::Invalid { field, .. }) if field == "cache.sentinel.nodes[2].host"
    ));
}

#[test]
fn validate_rejects_a_role_overrides_sentinel_with_an_empty_service_name() {
    let mut config = minimal_valid_config();
    let mut overridden = role_override();
    let mut sentinel = sentinel_config();
    sentinel.service_name = String::new();
    overridden.sentinel = Some(sentinel);
    config.cache.roles.coordination = Some(overridden);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::Invalid { field, .. })
            if field == "cache.roles.coordination.sentinel.service_name"
    ));
}

#[test]
fn trusted_proxy_cidr_matching_is_family_aware() {
    assert!(cidr_contains(
        "10.20.0.0/16",
        "10.20.30.40".parse().unwrap()
    ));
    assert!(!cidr_contains("10.20.0.0/16", "10.21.0.1".parse().unwrap()));
    assert!(cidr_contains(
        "fd00:dead:beef::/64",
        "fd00:dead:beef::1".parse().unwrap()
    ));
    assert!(!cidr_contains("10.20.0.0/16", "::1".parse().unwrap()));
}

#[test]
fn malformed_trusted_proxy_cidrs_are_rejected() {
    assert!(parse_cidr("10.20.0.0/33").is_none());
    assert!(parse_cidr("not-an-ip/24").is_none());
    assert!(parse_cidr("10.20.0.0").is_none());
}

#[test]
fn validate_passes_with_distributed_tracing_disabled_and_otlp_endpoint_unset() {
    let config = minimal_valid_config();
    assert!(!config.observability.enable_distributed_tracing);
    assert!(config.observability.otlp_endpoint.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_distributed_tracing_enabled_with_no_otlp_endpoint() {
    let mut config = minimal_valid_config();
    config.observability.enable_distributed_tracing = true;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("otlp_endpoint"));
}

#[test]
fn validate_rejects_distributed_tracing_enabled_with_a_blank_otlp_endpoint() {
    let mut config = minimal_valid_config();
    config.observability.enable_distributed_tracing = true;
    config.observability.otlp_endpoint = Some("   ".into());
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("otlp_endpoint"));
}

#[test]
fn validate_accepts_distributed_tracing_enabled_with_an_otlp_endpoint_set() {
    let mut config = minimal_valid_config();
    config.observability.enable_distributed_tracing = true;
    config.observability.otlp_endpoint = Some("http://otel-collector:4317".into());
    assert!(config.validate().is_ok());
}

#[test]
fn worker_health_port_defaults_on_when_omitted_from_config_json() {
    // minimal_valid_config()'s "observability" block never sets
    // worker_health_port — this asserts the #[serde(default = ...)] wiring
    // actually takes effect, not just that it compiles.
    let config = minimal_valid_config();
    assert_eq!(config.observability.worker_health_port, 9091);
}

#[test]
fn validate_rejects_worker_health_port_colliding_with_app_port() {
    let mut config = minimal_valid_config();
    config.app.port = 9091;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("observability.worker_health_port"));
}

#[test]
fn validate_rejects_worker_health_port_colliding_with_metrics_port() {
    let mut config = minimal_valid_config();
    config.observability.metrics_port = 9091;
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("observability.worker_health_port"));
}

#[test]
fn validate_accepts_worker_health_port_disabled() {
    let mut config = minimal_valid_config();
    config.observability.worker_health_port = 0;
    config.app.port = 9091;
    assert!(config.validate().is_ok());
}

/// `config_production_example_json_...` and `config_production_runtime_
/// example_json_...` below both reference the *same* real deployment env
/// var names (`DB_PASSWORD`, `JWT_SECRET`, etc. — unlike this module's
/// other `ATTOME_TEST_*`-prefixed env-var tests, these can't use unique
/// per-test names since they're proving the actual committed template
/// files' real `${VAR}` placeholders resolve). `cargo test` runs both
/// concurrently by default, and process env vars are global state, so
/// without this lock one test's `remove_var` can race the other's
/// `expand_env_vars` call and spuriously report vars as unresolved.
static PRODUCTION_CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// P-production-safety-profile's own closing checklist named this as
/// unverified: "only checked with `python -c json.load`, which proves
/// nothing about serde field-name/type correctness against the current
/// `AppConfig` struct shape." Live-verified here: the real committed
/// file (not a hand-copied fixture, via `include_str!` so this test
/// breaks the moment the file and this struct shape drift apart) must
/// deserialize into `AppConfig` and satisfy `app.deployment_profile =
/// "production"`'s own validation pass — the whole point of shipping an
/// example file is that it's a valid starting point, not just valid JSON.
#[test]
fn config_production_example_json_deserializes_and_passes_production_validation() {
    let _guard = PRODUCTION_CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let raw = include_str!("../../../../../config.production.example.json");

    // A template ships with every `${VAR}` unresolved by design — a real
    // deployment fills these from its own `.env`. Seed throwaway values
    // long enough to satisfy `check_secret`'s >=32-byte rule (D-002)
    // rather than skip expansion, so this test still proves the file's
    // *structure* deserializes and passes production validation once
    // resolved, not just that it's well-formed JSON.
    // SAFETY: serialized against the sibling runtime-example test via
    // PRODUCTION_CONFIG_ENV_LOCK above — both use these same fixed names.
    let throwaway_vars = [
        ("DB_PASSWORD", "throwaway-db-password-at-least-32-bytes-00"),
        (
            "DB_READONLY_PASSWORD",
            "throwaway-readonly-password-at-least-32-bytes-0",
        ),
        (
            "DB_MIGRATOR_PASSWORD",
            "throwaway-migrator-password-at-least-32-bytes-0",
        ),
        (
            "DB_RUNTIME_PASSWORD",
            "throwaway-runtime-password-at-least-32-bytes-00",
        ),
        (
            "CACHE_PASSWORD",
            "throwaway-cache-password-at-least-32-bytes-0",
        ),
        ("S3_ACCESS_KEY", "throwaway-s3-access-key"),
        (
            "S3_SECRET_KEY",
            "throwaway-s3-secret-key-at-least-32-bytes-000",
        ),
        (
            "JWT_SECRET",
            "throwaway-jwt-secret-at-least-32-bytes-000000",
        ),
        (
            "APIKEY_HASH_PEPPER",
            "throwaway-apikey-pepper-at-least-32-bytes-0000",
        ),
        ("OAUTH_GOOGLE_CLIENT_ID", "throwaway-google-client-id"),
        (
            "OAUTH_GOOGLE_CLIENT_SECRET",
            "throwaway-google-client-secret",
        ),
        ("SMTP_PASSWORD", "throwaway-smtp-password"),
        ("GOOGLE_AI_API_KEY", "throwaway-google-ai-api-key"),
        (
            "S2S_KEY_ENCRYPTION_KEY",
            "throwaway-s2s-key-at-least-32-bytes-000000000",
        ),
        ("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com"),
        // 64 hex — BCF-7 shape-checks the Ed25519 seed, not just its length.
        (
            "AUDIT_SIGNING_PRIVATE_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        // D-540 (audit plan item 2.7): production requires audit encryption.
        (
            "AUDIT_ERASURE_KEY_ENCRYPTION_KEY",
            "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
        ),
        // D-352's separate append-only anchor bucket. Adding a `${VAR}` to
        // config.production.example.json without adding it here fails the
        // assertion below, which is the intended coupling — but these two
        // reached the example file and not this list, so the test has been
        // red on `main`. Found and fixed 2026-08-12 while producing
        // TODO-010's verification record.
        ("ANCHOR_S3_ACCESS_KEY", "throwaway-anchor-access-key"),
        (
            "ANCHOR_S3_SECRET_KEY",
            "throwaway-anchor-secret-key-at-least-32-bytes",
        ),
    ];
    for (key, value) in throwaway_vars {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    // BCF-6 — expansion is structural: parse the template, then expand only
    // string values outside `_`-prefixed prose. The template's own
    // `_readme` literal "${VAR}" is therefore neither expanded nor reported,
    // and no VAR workaround is needed.
    let mut document: serde_json::Value =
        serde_json::from_str(raw).expect("config.production.example.json is valid JSON");
    let mut unresolved = Vec::new();
    expand_env_vars_in_value(&mut document, &mut unresolved);
    for (key, _) in throwaway_vars {
        unsafe {
            std::env::remove_var(key);
        }
    }
    assert!(
        unresolved.is_empty(),
        "config.production.example.json referenced a ${{VAR}} this test doesn't know about yet: {unresolved:?}"
    );

    // Every other `"__TODO__: ..."` placeholder in this file (hostnames,
    // URLs, filesystem paths) is now enforced by `validate_production_profile`'s
    // dedicated `check_not_placeholder` scan (see its call site) — swap in
    // the same kind of realistic value an operator following the file's
    // own `_readme` instruction would use, so this test proves a
    // *properly filled in* template validates cleanly, not that leaving
    // placeholders in place happens to validate anyway. The
    // `trusted_proxy_cidrs` entry doubles as the pre-existing CIDR-format
    // check's fixture.
    let placeholder_values = [
        (
            r#""__TODO__: real public hostname, e.g. app.customer.com""#,
            r#""app.customer.com""#,
        ),
        (
            r#""__TODO__: https://app.customer.com""#,
            r#""https://app.customer.com""#,
        ),
        (
            r#""__TODO__: production Postgres host (private network, not localhost)""#,
            r#""pg.internal""#,
        ),
        (
            r#""__TODO__: /etc/attome/tls/pg-ca.pem — CA cert for the Postgres endpoint above, deployment-provided (D-002)""#,
            r#""/etc/attome/tls/pg-ca.pem""#,
        ),
        (
            r#""__TODO__: production Redis/Dragonfly host (private network, not localhost)""#,
            r#""redis.internal""#,
        ),
        (
            r#""__TODO__: /etc/attome/tls/redis-ca.pem, if the endpoint uses a private CA""#,
            r#""/etc/attome/tls/redis-ca.pem""#,
        ),
        (
            r#""__TODO__: production S3-compatible endpoint, e.g. https://s3.customer-region.example.com""#,
            r#""https://s3.customer-region.example.com""#,
        ),
        (
            r#""__TODO__: host:port of a clamd daemon""#,
            r#""clamav.internal:3310""#,
        ),
        (
            r#""__TODO__: production SMTP host""#,
            r#""smtp.customer.com""#,
        ),
        (r#""__TODO__""#, r#""svc-attome""#),
        (
            r#""__TODO__: noreply@customer.com""#,
            r#""noreply@customer.com""#,
        ),
        (
            r#""__TODO__: nginx's private IP/CIDR, e.g. 10.0.0.0/24""#,
            r#""10.0.0.0/24""#,
        ),
    ];
    let mut document_text = document.to_string();
    for (placeholder, real_value) in placeholder_values {
        document_text = document_text.replace(placeholder, real_value);
    }

    // S12 (BCF-12e): the boot budget. Parsing plus validate() must stay far
    // under 250 ms; the bound is deliberately generous so only a real
    // regression (an accidental network call, a pathological parse) trips it
    // in a debug build.
    let started = std::time::Instant::now();
    let config: AppConfig = serde_json::from_str(&document_text)
        .expect("config.production.example.json must deserialize into AppConfig");
    assert_eq!(config.app.deployment_profile, "production");
    config
        .validate()
        .expect("config.production.example.json must itself pass production-profile validation");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(250),
        "production-template parse+validate took {elapsed:?}, over the 250 ms boot budget (S12)"
    );
}

/// P-bootstrap-credential-scoping (D-204) — same proof as the test above,
/// for the `server`/`worker` config variant: it must deserialize and pass
/// `validate_production_profile` too, with NO `DB_PASSWORD` env var set
/// at all (unlike the migrate-shaped test above, which sets it) — that
/// omission not breaking boot is the entire point of making
/// `database.password` an `Option`.
#[test]
fn config_production_runtime_example_json_deserializes_and_passes_production_validation() {
    let _guard = PRODUCTION_CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let raw = include_str!("../../../../../config.production.runtime.example.json");

    // Deliberately no DB_PASSWORD here — this file's database.password
    // is a literal `null`, not a `${DB_PASSWORD}` placeholder, so
    // unresolved-placeholder detection must pass without it.
    let throwaway_vars = [
        (
            "DB_READONLY_PASSWORD",
            "throwaway-readonly-password-at-least-32-bytes-0",
        ),
        (
            "DB_MIGRATOR_PASSWORD",
            "throwaway-migrator-password-at-least-32-bytes-0",
        ),
        (
            "DB_RUNTIME_PASSWORD",
            "throwaway-runtime-password-at-least-32-bytes-00",
        ),
        (
            "CACHE_PASSWORD",
            "throwaway-cache-password-at-least-32-bytes-0",
        ),
        ("S3_ACCESS_KEY", "throwaway-s3-access-key"),
        (
            "S3_SECRET_KEY",
            "throwaway-s3-secret-key-at-least-32-bytes-000",
        ),
        (
            "JWT_SECRET",
            "throwaway-jwt-secret-at-least-32-bytes-000000",
        ),
        (
            "APIKEY_HASH_PEPPER",
            "throwaway-apikey-pepper-at-least-32-bytes-0000",
        ),
        ("OAUTH_GOOGLE_CLIENT_ID", "throwaway-google-client-id"),
        (
            "OAUTH_GOOGLE_CLIENT_SECRET",
            "throwaway-google-client-secret",
        ),
        ("SMTP_PASSWORD", "throwaway-smtp-password"),
        ("GOOGLE_AI_API_KEY", "throwaway-google-ai-api-key"),
        (
            "S2S_KEY_ENCRYPTION_KEY",
            "throwaway-s2s-key-at-least-32-bytes-000000000",
        ),
        ("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com"),
        // 64 hex — BCF-7 shape-checks the Ed25519 seed, not just its length.
        (
            "AUDIT_SIGNING_PRIVATE_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        // D-540 (audit plan item 2.7): production requires audit encryption.
        (
            "AUDIT_ERASURE_KEY_ENCRYPTION_KEY",
            "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
        ),
    ];
    for (key, value) in throwaway_vars {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    // BCF-6 — structural expansion; see the sibling test above.
    let mut document: serde_json::Value =
        serde_json::from_str(raw).expect("config.production.runtime.example.json is valid JSON");
    let mut unresolved = Vec::new();
    expand_env_vars_in_value(&mut document, &mut unresolved);
    for (key, _) in throwaway_vars {
        unsafe {
            std::env::remove_var(key);
        }
    }
    assert!(
        unresolved.is_empty(),
        "config.production.runtime.example.json referenced a ${{VAR}} this test doesn't know \
         about yet: {unresolved:?}"
    );

    let placeholder_values = [
        (
            r#""__TODO__: real public hostname, e.g. app.customer.com""#,
            r#""app.customer.com""#,
        ),
        (
            r#""__TODO__: https://app.customer.com""#,
            r#""https://app.customer.com""#,
        ),
        (
            r#""__TODO__: production Postgres host (private network, not localhost)""#,
            r#""pg.internal""#,
        ),
        (
            r#""__TODO__: /etc/attome/tls/pg-ca.pem — CA cert for the Postgres endpoint above, deployment-provided (D-002)""#,
            r#""/etc/attome/tls/pg-ca.pem""#,
        ),
        (
            r#""__TODO__: production Redis/Dragonfly host (private network, not localhost)""#,
            r#""redis.internal""#,
        ),
        (
            r#""__TODO__: /etc/attome/tls/redis-ca.pem, if the endpoint uses a private CA""#,
            r#""/etc/attome/tls/redis-ca.pem""#,
        ),
        (
            r#""__TODO__: production S3-compatible endpoint, e.g. https://s3.customer-region.example.com""#,
            r#""https://s3.customer-region.example.com""#,
        ),
        (
            r#""__TODO__: host:port of a clamd daemon""#,
            r#""clamav.internal:3310""#,
        ),
        (
            r#""__TODO__: production SMTP host""#,
            r#""smtp.customer.com""#,
        ),
        (r#""__TODO__""#, r#""svc-attome""#),
        (
            r#""__TODO__: noreply@customer.com""#,
            r#""noreply@customer.com""#,
        ),
        (
            r#""__TODO__: nginx's private IP/CIDR, e.g. 10.0.0.0/24""#,
            r#""10.0.0.0/24""#,
        ),
    ];
    let mut document_text = document.to_string();
    for (placeholder, real_value) in placeholder_values {
        document_text = document_text.replace(placeholder, real_value);
    }

    let config: AppConfig = serde_json::from_str(&document_text)
        .expect("config.production.runtime.example.json must deserialize into AppConfig");
    assert_eq!(config.app.deployment_profile, "production");
    assert_eq!(
        config.database.password, None,
        "the whole point of this file — no bootstrap credential to deserialize"
    );
    config.validate().expect(
        "config.production.runtime.example.json must itself pass production-profile \
         validation with no database.password set",
    );
}

/// Negative-space counterpart to the test above: proves
/// `check_not_placeholder` actually blocks boot when an operator forgets
/// one field, instead of only being exercised in the all-fields-filled-in
/// happy path. Regression coverage for the gap an external review found —
/// pre-fix, every `__TODO__` placeholder in config.production.example.json
/// passed `validate()` unchanged.
#[test]
fn production_profile_rejects_unfilled_todo_placeholder() {
    let mut config = production_ready_config();
    config.database.host = "__TODO__: production Postgres host".into();
    let err = config
        .validate()
        .expect_err("a literal __TODO__ placeholder must fail production validation");
    assert!(format!("{err}").contains("database.host"));
}

/// The dev template must still describe today's non-production defaults
/// — this is the negative-space check for the test above: `expand_env_vars`
/// alone can't validate a config missing its `${VAR}` secrets (this file
/// ships with real throwaway values, not placeholders, so no expansion
/// step is needed), and `deployment_profile` must default to
/// `"development"` when the field is entirely absent, matching every
/// pre-P-production-safety-profile config already deployed.
#[test]
fn config_example_json_deserializes_with_development_profile_default() {
    let raw = include_str!("../../../../../config.example.json");
    let config: AppConfig =
        serde_json::from_str(raw).expect("config.example.json must deserialize into AppConfig");
    assert_eq!(config.app.deployment_profile, "development");
}

/// D-506, local-only: an embedding endpoint outside the deployment fails boot,
/// even when external providers are allowed for generation.
#[test]
fn validate_rejects_an_external_embedding_endpoint_even_when_external_providers_are_allowed() {
    let mut config = minimal_valid_config();
    config.inference.allow_external_provider = true;
    config.inference.embedding.base_url = "https://api.example.com/v1".into();
    let err = config
        .validate()
        .expect_err("an external embedding endpoint must fail boot");
    assert!(
        format!("{err}").contains("inference.embedding.base_url"),
        "{err}"
    );
}

/// No endpoint (lexical-only) and every in-deployment shape stay valid.
#[test]
fn validate_accepts_an_absent_or_in_deployment_embedding_endpoint() {
    for url in [
        "",
        "http://127.0.0.1:8088/v1",
        "http://tei:80/v1",
        "http://10.0.0.7:8080/v1",
    ] {
        let mut config = minimal_valid_config();
        config.inference.embedding.base_url = url.into();
        config
            .validate()
            .unwrap_or_else(|e| panic!("{url:?} must be accepted: {e}"));
    }
}

// ── D-558: public web chat (chatbot plan C9) ─────────────────────────────────

fn enabled_webchat(config: &mut AppConfig) {
    config.webchat.enabled = true;
    config.webchat.agent_definition_id = Some(uuid::Uuid::nil());
    config.webchat.session_token_cap = Some(20_000);
    config.webchat.daily_token_cap = Some(100_000);
    config.webchat.deployment_daily_token_cap = Some(400_000);
}

/// Disabled is the default and needs nothing else, so every existing
/// deployment keeps booting.
#[test]
fn webchat_is_disabled_by_default_and_needs_no_caps() {
    let config = minimal_valid_config();
    assert!(!config.webchat.enabled);
    config
        .validate()
        .expect("a disabled widget needs no configuration");
}

#[test]
fn webchat_enabled_with_a_definition_and_both_caps_is_valid() {
    let mut config = minimal_valid_config();
    enabled_webchat(&mut config);
    config.validate().expect("fully configured");
}

/// Enabled without any one of the bounds refuses to boot, naming the field —
/// never a silent fallback to an unrelated default budget.
#[test]
fn webchat_enabled_refuses_to_boot_without_each_bound() {
    type Break = fn(&mut AppConfig);
    let cases: [(&str, Break); 7] = [
        ("webchat.agent_definition_id", |c| {
            c.webchat.agent_definition_id = None
        }),
        ("webchat.session_token_cap", |c| {
            c.webchat.session_token_cap = None
        }),
        ("webchat.daily_token_cap", |c| {
            c.webchat.daily_token_cap = None
        }),
        ("webchat.session_token_cap", |c| {
            c.webchat.session_token_cap = Some(0)
        }),
        ("webchat.daily_token_cap", |c| {
            c.webchat.daily_token_cap = Some(0)
        }),
        ("webchat.deployment_daily_token_cap", |c| {
            c.webchat.deployment_daily_token_cap = None
        }),
        ("webchat.deployment_daily_token_cap", |c| {
            c.webchat.deployment_daily_token_cap = Some(0)
        }),
    ];
    for (field, break_it) in cases {
        let mut config = minimal_valid_config();
        enabled_webchat(&mut config);
        break_it(&mut config);
        let err = config.validate().expect_err(field);
        assert!(format!("{err}").contains(field), "{field}: {err}");
    }
}

/// An endpoint built in code gets the same safe timeout as one read from an
/// empty JSON object — never the zero a derived `Default` would give.
#[test]
fn an_inference_endpoint_default_has_the_safe_timeout() {
    let built = super::InferenceEndpoint::default();
    let parsed: super::InferenceEndpoint = serde_json::from_str("{}").expect("empty endpoint");
    assert_eq!(built.request_timeout_secs, 60);
    assert_eq!(built.request_timeout_secs, parsed.request_timeout_secs);
    assert!(built.base_url.is_empty() && built.model.is_empty() && built.api_key.is_none());
    assert_eq!(
        super::InferenceSection::default()
            .generation
            .request_timeout_secs,
        60,
        "a section built in code carries it too"
    );
}

// ── BCF Phase 0 (attome-config plan §6) — the failing tests land first ─────────
//
// Each test below is written against the defect the plan's §2.3 finding
// records and must fail until the named BCF-n item lands. They are not
// `#[ignore]`d: a red test IS the evidence the plan asks for while the item
// is open, and the item's acceptance command is this same test.

/// `KEY=VALUE` lines of a committed `.env` template, ignoring comments,
/// blanks and empty values. Values are taken verbatim — the templates use no
/// shell quoting.
fn template_env_values(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let (key, value) = (key.trim(), value.trim());
            (!key.is_empty() && !value.is_empty()).then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

/// Give the production fixture every optional credential slot the `.env`
/// templates fill, so applying a template value to one of them is a real
/// test rather than a silent no-op on a `None`.
fn production_config_with_credential_slots() -> AppConfig {
    let mut config = production_ready_config();
    config.database.readonly = Some(ReadonlyDbCredentials {
        user: "attome_readonly".into(),
        password: "throwaway-readonly-password-32-bytes-0".into(),
        host: None,
        port: None,
    });
    config.database.migrator = Some(MigratorDbCredentials {
        user: "attome_migrator".into(),
        password: "throwaway-migrator-password-32-bytes-0".into(),
    });
    config.audit.anchor_store = Some(compliant_anchor_store());
    config
}

/// Apply one shipped `.env` template value to the config field it feeds.
/// Returns `false` for a key this crate does not read (backup, restore-drill
/// and local-dev-login variables are other tools' secrets).
fn apply_template_secret(config: &mut AppConfig, key: &str, value: &str) -> bool {
    match key {
        "JWT_SECRET" => config.auth.jwt_secret = KeyRing::single(value.into()),
        "APIKEY_HASH_PEPPER" => config.auth.apikey_hash_pepper = value.into(),
        "DB_PASSWORD" => config.database.password = Some(value.into()),
        "DB_READONLY_PASSWORD" => {
            config
                .database
                .readonly
                .as_mut()
                .expect("credential slot set by fixture")
                .password = value.into();
        }
        "DB_MIGRATOR_PASSWORD" => {
            config
                .database
                .migrator
                .as_mut()
                .expect("credential slot set by fixture")
                .password = value.into();
        }
        "DB_RUNTIME_PASSWORD" => {
            config
                .database
                .runtime
                .as_mut()
                .expect("credential slot set by fixture")
                .password = value.into();
        }
        "CACHE_PASSWORD" => config.cache.password = value.into(),
        "S3_ACCESS_KEY" => config.storage.s3_access_key = value.into(),
        "S3_SECRET_KEY" => config.storage.s3_secret_key = value.into(),
        "SMTP_PASSWORD" => config.email.smtp_password = value.into(),
        "OAUTH_GOOGLE_CLIENT_SECRET" => config.auth.oauth_google_client_secret = value.into(),
        "GOOGLE_AI_API_KEY" => config.google_ai.api_key = value.into(),
        "S2S_KEY_ENCRYPTION_KEY" => config.s2s.key_encryption_key = KeyRing::single(value.into()),
        "AUDIT_SIGNING_PRIVATE_KEY" => config.audit.signing_private_key = value.into(),
        "AUDIT_ERASURE_KEY_ENCRYPTION_KEY" => {
            config.audit.erasure_key_encryption_key = KeyRing::single(value.into());
        }
        "AI_PROVIDER_CREDENTIAL_KEY" => {
            config.inference.provider_credential_key = KeyRing::single(value.into());
        }
        "ANCHOR_S3_ACCESS_KEY" => {
            config
                .audit
                .anchor_store
                .as_mut()
                .expect("credential slot set by fixture")
                .s3_access_key = value.into();
        }
        "ANCHOR_S3_SECRET_KEY" => {
            config
                .audit
                .anchor_store
                .as_mut()
                .expect("credential slot set by fixture")
                .s3_secret_key = value.into();
        }
        _ => return false,
    }
    true
}

/// BCF-D1: the shipped-template denylist must stay a production-profile rule.
/// The dev stack deliberately boots on `config.example.json`'s throwaway
/// secrets, and refusing those in development would break every local setup.
#[test]
fn template_secret_values_are_accepted_outside_production() {
    let config = minimal_valid_config();
    assert_eq!(config.app.deployment_profile, "development");
    assert!(
        config
            .auth
            .jwt_secret
            .active()
            .unwrap_or("")
            .contains("test-only-throwaway"),
        "fixture must actually carry a template value, or this test proves nothing"
    );
    config
        .validate()
        .expect("development must keep accepting throwaway template values (BCF-D1)");
}

/// BCF-P0.1 (finding BCF-F1): every secret value the shipped `.env` templates
/// put in front of an operator must be refused by the production profile,
/// including the credentials `check_secret` never saw (DB/cache passwords, S3
/// keys). Reads the committed templates themselves, so a new shipped secret
/// cannot be added without landing here.
#[test]
fn production_refuses_every_shipped_template_secret() {
    let templates = [
        (".env.example", include_str!("../../../../../.env.example")),
        (
            ".env.runtime.example",
            include_str!("../../../../../.env.runtime.example"),
        ),
    ];
    let mut checked = 0usize;
    for (file, text) in templates {
        for (key, value) in template_env_values(text) {
            let mut config = production_config_with_credential_slots();
            if !apply_template_secret(&mut config, &key, &value) {
                continue;
            }
            checked += 1;
            let result = config.validate();
            assert!(
                result.is_err(),
                "{file}: the shipped template value {key}={value:?} passed production \
                 validate() — a publicly known secret must never boot a production node"
            );
        }
    }
    assert!(
        checked >= 8,
        "expected to exercise the shipped template secrets; only {checked} mapped to a field"
    );
}

/// BCF-P0.4 (finding BCF-F4a): a secret that contains a backslash-n, a double
/// quote or a backslash must reach `database.password` byte-for-byte. The
/// textual `expand_env_vars` splice JSON-decodes it (or breaks the parse).
#[test]
fn expanded_secret_arrives_byte_for_byte() {
    const ENV_KEY: &str = "ATTOME_TEST_BCF_P0_4_SECRET";
    // Literal backslash-n, double quote, double backslash.
    const RAW: &str = r#"a\nb"c\\d"#;
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let placeholder = ["$", "{", ENV_KEY, "}"].concat();
    let path = std::env::temp_dir().join("attome_test_bcf_p0_4_byte_for_byte.json");
    let mut document: serde_json::Value =
        serde_json::from_str(MINIMAL_VALID_JSON).expect("fixture is valid JSON");
    document["database"]["password"] = serde_json::Value::String(placeholder);
    std::fs::write(&path, document.to_string()).expect("temp config written");

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; all three vars are
    // set to controlled values and cleaned up before returning.
    unsafe {
        std::env::set_var(ENV_KEY, RAW);
        std::env::set_var("CONFIG_FILE", &path);
        std::env::set_var("APP_ENV", "test-sentinel-not-debug");
    }
    let result = AppConfig::from_file();
    // SAFETY: same vars set above.
    unsafe {
        std::env::remove_var(ENV_KEY);
        std::env::remove_var("CONFIG_FILE");
        std::env::remove_var("APP_ENV");
    }
    std::fs::remove_file(&path).ok();

    let config = result.expect("from_file must resolve the placeholder and parse the config");
    assert_eq!(
        config.database.password.as_ref().map(|p| p.expose()),
        Some(RAW),
        "the expanded secret must arrive byte-for-byte, never JSON-decoded"
    );
}

/// BCF-P0.5 (finding BCF-F5): key material is shape-checked, not
/// length-checked. A non-hex `audit.signing_private_key` passes today and
/// panics later in `XrmState::new`.
#[test]
fn validate_rejects_non_hex_signing_key() {
    let mut config = production_ready_config();
    config.audit.signing_private_key = "not-a-hex-key-not-a-hex-key-not-a-hex-key-1234".into();
    let err = config
        .validate()
        .expect_err("a non-hex signing key must be refused");
    assert!(
        format!("{err}").contains("audit.signing_private_key"),
        "{err}"
    );

    let mut config = production_ready_config();
    config.audit.signing_private_key = "ab".repeat(20).into();
    let err = config
        .validate()
        .expect_err("a 40-hex-char signing key must be refused");
    assert!(
        format!("{err}").contains("audit.signing_private_key"),
        "{err}"
    );

    assert!(
        production_ready_config().validate().is_ok(),
        "the 64-hex fixture must stay valid"
    );
}

/// BCF-5 (finding BCF-F7, D-615): the production profile refuses an unresolved
/// placeholder whatever `APP_ENV` says. `APP_ENV=debug` used to relax the
/// from_file gate even for a production-profile file, turning an unset secret
/// into an opaque DNS/auth failure at first use.
#[test]
fn production_profile_rejects_unresolved_placeholder_under_app_env_debug() {
    const UNSET_KEY: &str = "ATTOME_TEST_BCF_5_UNSET";
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let path = std::env::temp_dir().join("attome_test_bcf_5_production_unresolved.json");
    let mut document: serde_json::Value =
        serde_json::from_str(MINIMAL_VALID_JSON).expect("fixture is valid JSON");
    document["app"]["deployment_profile"] = serde_json::Value::String("production".into());
    document["database"]["host"] = serde_json::Value::String(["$", "{", UNSET_KEY, "}"].concat());
    std::fs::write(&path, document.to_string()).expect("temp config written");

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; both vars are set
    // to controlled values and cleaned up before returning.
    unsafe {
        std::env::set_var("CONFIG_FILE", &path);
        std::env::set_var("APP_ENV", "debug");
        std::env::remove_var(UNSET_KEY);
    }
    let result = AppConfig::from_file();
    // SAFETY: same vars set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::remove_var("APP_ENV");
    }
    std::fs::remove_file(&path).ok();

    assert!(
        matches!(result, Err(ConfigError::UnresolvedPlaceholders { .. })),
        "a production profile must refuse an unresolved placeholder under APP_ENV=debug, got {:?}",
        result.map(|config| config.app.deployment_profile)
    );
}

// ── BCF-16 (finding BCF-F16): portal secret shape rules ──────────────────────

fn portal_with_oidc(client_secret: &str) -> PortalSection {
    let mut portal = PortalSection::default();
    portal.oidc_providers.insert(
        "entra".into(),
        OidcProviderConfig {
            display_name: "Entra".into(),
            issuer: "https://idp.example.com".into(),
            client_id: "portal-client".into(),
            client_secret: client_secret.into(),
            scopes: default_oidc_scopes(),
            email_claim: default_oidc_email_claim(),
            require_email_verified_claim: true,
            mfa_acr_values: Vec::new(),
            trust_idp_mfa: true,
        },
    );
    portal
}

#[test]
fn portal_secret_with_unresolved_placeholder_is_refused() {
    let mut config = minimal_valid_config();
    config.portal = portal_with_oidc(&["$", "{", "PORTAL_CLIENT_SECRET", "}"].concat());
    let err = config.validate().unwrap_err();
    assert!(
        format!("{err}").contains("portal.oidc_providers.entra.client_secret"),
        "{err}"
    );
}

#[test]
fn portal_client_secret_below_minimum_is_refused() {
    let mut config = minimal_valid_config();
    config.portal = portal_with_oidc("too-short");
    let err = config.validate().unwrap_err();
    assert!(
        format!("{err}").contains("portal.oidc_providers.entra.client_secret"),
        "{err}"
    );
}

#[test]
fn portal_client_secret_at_the_minimum_is_accepted() {
    let mut config = minimal_valid_config();
    config.portal = portal_with_oidc(&"a".repeat(16));
    assert!(config.validate().is_ok());
}

#[test]
fn portal_captcha_secret_below_minimum_is_refused() {
    let mut config = minimal_valid_config();
    config.portal.captcha = CaptchaConfig {
        provider: CaptchaProvider::Turnstile,
        secret: "short-secret".into(),
        timeout_ms: 3_000,
        ..CaptchaConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("portal.captcha.secret"), "{err}");
}

#[test]
fn portal_captcha_secret_at_the_minimum_is_accepted() {
    let mut config = minimal_valid_config();
    config.portal.captcha = CaptchaConfig {
        provider: CaptchaProvider::Turnstile,
        secret: "a".repeat(32).into(),
        timeout_ms: 3_000,
        ..CaptchaConfig::default()
    };
    assert!(config.validate().is_ok());
}

/// The portal template denylist follows BCF-D1: production only.
#[test]
fn portal_template_secret_is_refused_only_in_production() {
    let mut dev = minimal_valid_config();
    dev.portal = portal_with_oidc("change_me_portal_secret_value_here");
    assert!(
        dev.validate().is_ok(),
        "development keeps accepting throwaway template values (BCF-D1)"
    );

    let mut prod = production_ready_config();
    prod.portal = portal_with_oidc("change_me_portal_secret_value_here");
    let err = prod.validate().unwrap_err();
    assert!(
        format!("{err}").contains("portal.oidc_providers.entra.client_secret"),
        "{err}"
    );
}

// ── BCF-9: connection strings bracket IPv6 hosts ─────────────────────────────

#[test]
fn database_url_brackets_an_ipv6_host() {
    let mut config = minimal_valid_config();
    config.database.host = "2001:db8::5".into();
    let url = config.database_url();
    assert!(
        url.contains("@[2001:db8::5]:5555/test"),
        "an IPv6 literal must be bracketed or the URL is unparseable: {url}"
    );
}

#[test]
fn redis_url_brackets_an_ipv6_host() {
    let mut config = minimal_valid_config();
    config.cache.host = "fd00::7".into();
    assert_eq!(config.redis_url(), "redis://[fd00::7]:6379/0");
}

#[test]
fn redis_sentinel_url_brackets_ipv6_hosts() {
    let mut config = minimal_valid_config();
    config.cache.host = "fd00::7".into();
    config.cache.sentinel = Some(CacheSentinelConfig {
        service_name: "mymaster".into(),
        nodes: vec![CacheSentinelNode {
            host: "fd00::8".into(),
            port: 26379,
        }],
        sentinel_username: None,
        sentinel_password: None,
    });
    let url = config.redis_url();
    assert!(url.contains("redis-sentinel://[fd00::7]:6379/0"), "{url}");
    assert!(url.contains("&node=[fd00::8]:26379"), "{url}");
}

// ── BCF-7: key-material shape ────────────────────────────────────────────────

/// A 64-character value that is the right length but not hex — the shape a
/// length-only `check_secret` cannot tell apart from real key material.
fn non_hex_64() -> String {
    "z".repeat(64)
}

fn hex_64() -> String {
    "ab".repeat(32)
}

#[test]
fn validate_rejects_non_hex_key_material_rings() {
    type Break = fn(&mut AppConfig);
    let cases: [(&str, Break); 6] = [
        ("auth.mfa_encryption_key", |c| {
            c.auth.mfa_policy = "optional".into();
            c.auth.mfa_encryption_key = KeyRing::single(non_hex_64());
        }),
        ("s2s.key_encryption_key", |c| {
            c.s2s.enabled = true;
            c.s2s.key_encryption_key = KeyRing::single(non_hex_64());
        }),
        ("integration.credential_encryption_key", |c| {
            c.integration.enabled = true;
            c.integration.credential_encryption_key = KeyRing::single(non_hex_64());
        }),
        ("einvoice.key_encryption_key", |c| {
            c.einvoice.enabled = true;
            c.einvoice.key_encryption_key = KeyRing::single(non_hex_64());
        }),
        ("audit.erasure_key_encryption_key", |c| {
            c.audit.erasure_key_encryption_key = KeyRing::single(non_hex_64());
        }),
        ("inference.provider_credential_key", |c| {
            c.inference.provider_credential_key = KeyRing::single(non_hex_64());
        }),
    ];
    for (field, break_it) in cases {
        let mut config = minimal_valid_config();
        break_it(&mut config);
        let err = config
            .validate()
            .expect_err(&format!("{field} must be shape-checked"));
        assert!(format!("{err}").contains(field), "{field}: {err}");
    }
}

#[test]
fn validate_accepts_64_hex_key_material_rings() {
    let mut config = minimal_valid_config();
    config.auth.mfa_policy = "optional".into();
    config.auth.mfa_encryption_key = KeyRing::single(hex_64());
    config.s2s.enabled = true;
    config.s2s.key_encryption_key = KeyRing::single(hex_64());
    config.integration.enabled = true;
    config.integration.credential_encryption_key = KeyRing::single(hex_64());
    config.einvoice.enabled = true;
    config.einvoice.key_encryption_key = KeyRing::single(hex_64());
    config.audit.erasure_key_encryption_key = KeyRing::single(hex_64());
    config.inference.provider_credential_key = KeyRing::single(hex_64());
    config
        .validate()
        .unwrap_or_else(|e| panic!("64 hex characters must be accepted: {e}"));
}

/// An empty `provider_credential_key` is the documented "no AI provider
/// credential configured" state and must stay valid.
#[test]
fn validate_accepts_an_unset_provider_credential_key() {
    let config = minimal_valid_config();
    assert!(config.inference.provider_credential_key.is_empty());
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_a_key_ring_with_an_empty_or_non_printable_id() {
    for (keys_json, active) in [
        (serde_json::json!({ "": "z".repeat(40) }), ""),
        (serde_json::json!({ "bad\tid": "z".repeat(40) }), "bad\tid"),
    ] {
        let mut config = minimal_valid_config();
        config.auth.jwt_secret = serde_json::from_value(serde_json::json!({
            "keys": keys_json,
            "active_key_id": active,
        }))
        .expect("ring fixture must deserialize");
        let err = config.validate().unwrap_err();
        assert!(format!("{err}").contains("auth.jwt_secret"), "{err}");
    }
}

// ── BCF-6: structural placeholder expansion ──────────────────────────────────

/// A `${...}` under a `_`-prefixed key is prose: not expanded, and not
/// reported as a required variable. A placeholder in a real value is both
/// expanded and, if unset, reported with its JSON path.
#[test]
fn readme_prose_placeholders_are_neither_expanded_nor_reported() {
    let mut document: serde_json::Value = serde_json::from_str(
        r#"{"_readme": "use ${ANY_VAR} here", "app": {"frontend_host": "${ALSO_UNSET}"}}"#,
    )
    .expect("document");
    let mut unresolved = Vec::new();
    expand_env_vars_in_value(&mut document, &mut unresolved);

    assert_eq!(
        document["_readme"], "use ${ANY_VAR} here",
        "prose must be left byte-for-byte"
    );
    assert_eq!(unresolved.len(), 1, "only the real value is reported");
    assert!(unresolved[0].contains("ALSO_UNSET"), "{}", unresolved[0]);
    assert!(
        unresolved[0].contains("app.frontend_host"),
        "the report must name the JSON path: {}",
        unresolved[0]
    );
}

/// A `${...}` outside a JSON string is invalid JSON; the parse error says so
/// rather than leaving the operator with a bare column number (BCF-6).
#[test]
fn from_file_hints_when_a_placeholder_is_outside_a_string() {
    let _guard = CONFIG_FILE_PATH_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = std::env::temp_dir().join("attome_test_bcf_6_placeholder_outside_string.json");
    std::fs::write(&path, r#"{ "app": { "port": ${ATTOME_TEST_BCF_6_PORT} } }"#)
        .expect("temp config written");

    // SAFETY: serialized by CONFIG_FILE_PATH_ENV_LOCK above; both vars are set
    // to controlled values and cleaned up before returning.
    unsafe {
        std::env::set_var("CONFIG_FILE", &path);
        std::env::set_var("APP_ENV", "test-sentinel-not-debug");
    }
    let result = AppConfig::from_file();
    // SAFETY: same vars set above.
    unsafe {
        std::env::remove_var("CONFIG_FILE");
        std::env::remove_var("APP_ENV");
    }
    std::fs::remove_file(&path).ok();

    let err = result.expect_err("invalid JSON must be a Parse error");
    let message = format!("{err}");
    assert!(
        message.contains("outside a JSON string value"),
        "the parse error must point at the real cause: {message}"
    );
}

// ── BCF-11: error classification ─────────────────────────────────────────────

/// Range/format/enum mistakes are `Invalid` (fix the value); a posture that
/// weakens security is `Insecure` (fix the policy). Both keep naming the field.
#[test]
fn range_and_format_errors_are_invalid_and_security_errors_are_insecure() {
    let mut config = minimal_valid_config();
    config.database.timeout = 0.0;
    assert!(
        matches!(config.validate(), Err(ConfigError::Invalid { ref field, .. }) if field == "database.timeout"),
        "a range error must be Invalid"
    );

    let mut config = minimal_valid_config();
    config.database.ssl_mode = "nope".into();
    assert!(
        matches!(config.validate(), Err(ConfigError::Invalid { ref field, .. }) if field == "database.ssl_mode"),
        "an enum error must be Invalid"
    );

    let mut config = production_ready_config();
    config.cache.tls_enabled = false;
    assert!(
        matches!(config.validate(), Err(ConfigError::Insecure { .. })),
        "a production refusal must stay Insecure"
    );

    let mut config = minimal_valid_config();
    config.auth.jwt_secret = KeyRing::single("short".into());
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Insecure { .. }),
        "a weak secret must stay Insecure: {err}"
    );
    assert!(format!("{err}").contains("auth.jwt_secret"), "{err}");
}

// ── BCF-10: unknown-key reporting ────────────────────────────────────────────

/// A typo'd key is reported by its JSON path instead of being dropped.
#[test]
fn csrf_enforced_typo_is_reported() {
    let json = MINIMAL_VALID_JSON.replace(
        r#""rate_limit""#,
        r#""security": { "csrf_enforced": true }, "rate_limit""#,
    );
    let (_config, ignored) = AppConfig::deserialize_tracked(&json).expect("must parse");
    assert_eq!(ignored, vec!["security.csrf_enforced".to_string()]);
}

/// `_`-prefixed keys are prose, not typos: neither the top-level `_readme`
/// nor a nested `_comment` is reported.
#[test]
fn comment_keys_are_not_reported() {
    let json = MINIMAL_VALID_JSON.replace(
        r#""rate_limit""#,
        r#""_readme": "docs", "security": { "_csrf_enforce_comment": "x" }, "rate_limit""#,
    );
    let (_config, ignored) = AppConfig::deserialize_tracked(&json).expect("must parse");
    assert!(
        ignored.is_empty(),
        "comment/prose keys must not be reported: {ignored:?}"
    );
}

/// BCF-12(a) — every committed template is deserializable with zero unknown
/// keys, so the templates cannot drift behind the schema.
#[test]
fn every_template_has_zero_unknown_keys() {
    for (name, raw) in [
        (
            "config.example.json",
            include_str!("../../../../../config.example.json"),
        ),
        (
            "config.production.example.json",
            include_str!("../../../../../config.production.example.json"),
        ),
        (
            "config.production.runtime.example.json",
            include_str!("../../../../../config.production.runtime.example.json"),
        ),
    ] {
        let (_config, ignored) = AppConfig::deserialize_tracked(raw)
            .unwrap_or_else(|e| panic!("{name} must deserialize into AppConfig: {e}"));
        assert!(
            ignored.is_empty(),
            "{name} carries unknown keys: {ignored:?}"
        );
    }
}

// ── BCF-12: template and default parity ──────────────────────────────────────

/// (b) the dev template is a valid starting point, not just valid JSON: with
/// throwaway values for its \`\${VAR}\`s it deserializes and passes `validate()`.
#[test]
fn config_example_json_passes_validation_with_its_dummy_values() {
    let _guard = PRODUCTION_CONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let raw = include_str!("../../../../../config.example.json");

    // Key-material fields are 64 hex (BCF-7); connection credentials are not
    // shape-checked but must resolve.
    let throwaway_vars = [
        ("DB_PASSWORD", "throwaway-db-password-at-least-32-bytes-00"),
        (
            "DB_READONLY_PASSWORD",
            "throwaway-readonly-password-at-least-32-bytes-0",
        ),
        (
            "DB_MIGRATOR_PASSWORD",
            "throwaway-migrator-password-at-least-32-bytes-0",
        ),
        (
            "DB_RUNTIME_PASSWORD",
            "throwaway-runtime-password-at-least-32-bytes-00",
        ),
        ("S3_ACCESS_KEY", "throwaway-s3-access-key"),
        (
            "S3_SECRET_KEY",
            "throwaway-s3-secret-key-at-least-32-bytes-000",
        ),
        (
            "JWT_SECRET",
            "throwaway-jwt-secret-at-least-32-bytes-000000",
        ),
        (
            "APIKEY_HASH_PEPPER",
            "throwaway-apikey-pepper-at-least-32-bytes-0000",
        ),
        ("OAUTH_GOOGLE_CLIENT_ID", "throwaway-google-client-id"),
        (
            "OAUTH_GOOGLE_CLIENT_SECRET",
            "throwaway-google-client-secret",
        ),
        ("SMTP_PASSWORD", "throwaway-smtp-password"),
        ("GOOGLE_AI_API_KEY", "throwaway-google-ai-api-key"),
        (
            "S2S_KEY_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        (
            "EVENTS_WEBHOOK_SIGNING_KEY",
            "throwaway-webhook-signing-key-at-least-32-bytes-0",
        ),
        (
            "INTEGRATION_CREDENTIAL_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        (
            "AI_PROVIDER_CREDENTIAL_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        (
            "AUDIT_SIGNING_PRIVATE_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
    ];
    for (key, value) in throwaway_vars {
        // SAFETY: serialized against the sibling production-template tests via
        // PRODUCTION_CONFIG_ENV_LOCK above.
        unsafe {
            std::env::set_var(key, value);
        }
    }
    let mut document: serde_json::Value =
        serde_json::from_str(raw).expect("config.example.json is valid JSON");
    let mut unresolved = Vec::new();
    expand_env_vars_in_value(&mut document, &mut unresolved);
    for (key, _) in throwaway_vars {
        // SAFETY: same vars set above.
        unsafe {
            std::env::remove_var(key);
        }
    }
    assert!(unresolved.is_empty(), "unresolved: {unresolved:?}");

    let config: AppConfig =
        serde_json::from_value(document).expect("config.example.json must deserialize");
    assert_eq!(config.app.deployment_profile, "development");
    config
        .validate()
        .expect("config.example.json must itself pass validate() (BCF-12b)");
}

/// (c) D-205: every section AppConfig defaults must have its Default equal to
/// deserializing an empty object -- the footgun a derived Default reopens by
/// zeroing a serde default.
#[test]
fn defaulted_sections_default_equals_an_empty_object() {
    macro_rules! check {
        ($($ty:ty),+ $(,)?) => {
            $(
                let built = <$ty>::default();
                let parsed: $ty = serde_json::from_str("{}").unwrap_or_else(|e| {
                    panic!("{} must deserialize from an empty object: {e}", stringify!($ty))
                });
                assert_eq!(
                    format!("{built:?}"),
                    format!("{parsed:?}"),
                    "{}: Default must equal deserializing {{}} (D-205)",
                    stringify!($ty)
                );
            )+
        };
    }
    check!(
        super::S2SSection,
        super::SecuritySection,
        super::AuditSection,
        super::NotificationSection,
        super::RetentionSection,
        super::CorsSection,
        super::JobsSection,
        super::QuerySection,
        super::OidcSection,
        super::IdempotencySection,
        super::ApprovalSection,
        super::DeploymentSection,
        super::CapabilitySection,
        super::InferenceSection,
        super::WebcrawlSection,
        super::WebchatSection,
        super::PortalSection,
        super::EventsSection,
        super::IntegrationSection,
        super::DocgenSection,
        super::ChangeFeedSection,
    );
}

/// (d) every AppConfig field is a top-level key in the dev template, parsed
/// out of config/mod.rs so a new section cannot land without a template block.
#[test]
fn every_appconfig_section_is_present_in_the_dev_template() {
    let source = include_str!("mod.rs");
    let body = source
        .split_once("pub struct AppConfig {")
        .expect("AppConfig must be declared in config/mod.rs")
        .1;
    let body = body
        .split_once("\n}")
        .expect("AppConfig body must terminate")
        .0;
    let fields: Vec<&str> = body
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("pub ")
                .and_then(|rest| rest.split(':').next())
                .map(str::trim)
        })
        .filter(|name| !name.is_empty())
        .collect();
    assert!(
        fields.len() >= 30,
        "the AppConfig field parser drifted: {fields:?}"
    );

    let template: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../config.example.json"))
            .expect("config.example.json is valid JSON");
    let missing: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|field| template.get(field).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "config.example.json is missing section(s): {missing:?} (BCF-12d)"
    );
}

/// BIN-D7 — the retired `inference.caller_token_budget_per_min` still loads
/// (it is not an unknown key) but is reported as deprecated; unset, nothing is.
#[test]
fn a_retired_inference_budget_key_is_reported_as_deprecated() {
    let template = include_str!("../../../../../config.example.json");
    let (config, _) = AppConfig::deserialize_tracked(template).expect("template loads");
    assert!(config.deprecated_keys().is_empty());

    let mut value: serde_json::Value = serde_json::from_str(template).expect("valid JSON");
    value["inference"]["caller_token_budget_per_min"] = serde_json::json!(20_000);
    let raw = serde_json::to_string(&value).expect("serialize");
    let (config, ignored) = AppConfig::deserialize_tracked(&raw).expect("still loads");
    assert!(
        ignored.is_empty(),
        "a retired key is not an unknown key: {ignored:?}"
    );
    let paths: Vec<&str> = config.deprecated_keys().iter().map(|(p, _)| *p).collect();
    assert_eq!(paths, ["inference.caller_token_budget_per_min"]);
}

/// (d) second half: every key the dev template carries is either in each
/// production template or explained by a `_`-prefixed comment there — a
/// sibling comment that names the key, or a top-level `_<section>_comment`
/// for a whole omitted section.
#[test]
fn production_templates_carry_every_dev_key_or_a_comment() {
    let dev: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../config.example.json"))
            .expect("config.example.json is valid JSON");
    let dev = dev.as_object().expect("dev template is an object");
    for (name, raw) in [
        (
            "config.production.example.json",
            include_str!("../../../../../config.production.example.json"),
        ),
        (
            "config.production.runtime.example.json",
            include_str!("../../../../../config.production.runtime.example.json"),
        ),
    ] {
        let prod: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
        let prod = prod.as_object().expect("template is an object");
        let mut unexplained = Vec::new();
        for (section, dev_block) in dev.iter().filter(|(k, _)| !k.starts_with('_')) {
            let Some(prod_block) = prod.get(section) else {
                if !prod.contains_key(&format!("_{section}_comment")) {
                    unexplained.push(section.clone());
                }
                continue;
            };
            let (Some(dev_block), Some(prod_block)) =
                (dev_block.as_object(), prod_block.as_object())
            else {
                continue;
            };
            let comments: String = prod_block
                .iter()
                .filter(|(k, _)| k.starts_with('_'))
                .filter_map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            for key in dev_block.keys().filter(|k| !k.starts_with('_')) {
                if !prod_block.contains_key(key) && !comments.contains(key.as_str()) {
                    unexplained.push(format!("{section}.{key}"));
                }
            }
        }
        assert!(
            unexplained.is_empty(),
            "{name} omits {unexplained:?} with no `_` comment saying why (BCF-12d)"
        );
    }
}

#[test]
fn the_kdf_defaults_equal_the_former_constants_and_validate() {
    let config = minimal_valid_config();
    let kdf = &config.auth.kdf;
    assert_eq!(kdf.hard_cap, 6);
    assert_eq!(kdf.memory_budget_bytes, 256 * 1024 * 1024);
    assert_eq!(kdf.acquire_timeout_ms, 2000);
    assert_eq!(kdf.argon2_m_cost, 19_456);
    assert_eq!(kdf.argon2_t_cost, 2);
    assert_eq!(kdf.password_min_length, 12);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_kdf_parameters_below_the_floor() {
    type Weaken = fn(&mut AppConfig);
    let cases: [(&str, Weaken); 6] = [
        ("argon2_m_cost", |c| c.auth.kdf.argon2_m_cost = 19_455),
        ("argon2_t_cost", |c| c.auth.kdf.argon2_t_cost = 1),
        ("password_min_length", |c| {
            c.auth.kdf.password_min_length = 11
        }),
        ("hard_cap", |c| c.auth.kdf.hard_cap = 0),
        ("acquire_timeout_ms", |c| c.auth.kdf.acquire_timeout_ms = 99),
        ("memory_budget_bytes", |c| {
            c.auth.kdf.memory_budget_bytes = 1024
        }),
    ];
    for (field, weaken) in cases {
        let mut config = minimal_valid_config();
        weaken(&mut config);
        let err = config.validate().expect_err(field);
        assert!(
            format!("{err}").contains(&format!("auth.kdf.{field}")),
            "{field}: {err}"
        );
    }
}

#[test]
fn validate_rejects_kdf_parameters_above_the_ceiling() {
    let mut config = minimal_valid_config();
    config.auth.kdf.argon2_t_cost = 11;
    assert!(format!("{}", config.validate().unwrap_err()).contains("auth.kdf.argon2_t_cost"));
}

/// Solution 7 Phase 2 design §10.5: a set but malformed
/// `metadata.release_report.notify_roles` fails boot; unset and a valid list
/// pass.
#[test]
fn validate_checks_the_release_report_notify_roles() {
    let mut config = minimal_valid_config();
    assert!(config.validate().is_ok());
    config.metadata.release_report.notify_roles = Some(vec!["Release Manager".into()]);
    assert!(config.validate().is_ok());
    config.metadata.release_report.notify_roles = Some(Vec::new());
    assert!(
        format!("{}", config.validate().unwrap_err())
            .contains("metadata.release_report.notify_roles")
    );
}

/// U1-T5 — the sovereign preset is off by default, and once on it refuses any
/// destination outside the deployment while allowing the operator's own.
#[test]
fn sovereign_preset_refuses_outside_destinations() {
    let mut config = minimal_valid_config();
    assert!(!config.deployment.sovereign);
    config.google_ai.api_key = String::new().into();
    // Everything in the minimal config is local except nothing: clean.
    assert_eq!(
        config.sovereign_violations(),
        Vec::<(String, String)>::new()
    );

    config.deployment.sovereign = true;
    config.inference.generation.base_url = "https://api.openai.com/v1".into();
    let err = config.validate().unwrap_err();
    assert!(format!("{err}").contains("inference.generation.base_url"));

    // A model server on the private network is inside.
    config.inference.generation.base_url = "http://10.0.0.5:8000/v1".into();
    config.email.enabled = true;
    config.email.smtp_host = "mail.example.gov".into();
    let fields: Vec<String> = config
        .sovereign_violations()
        .into_iter()
        .map(|(field, _)| field)
        .collect();
    assert_eq!(fields, ["email.smtp_host"]);

    // Unless the operator names that relay as theirs.
    config.deployment.sovereign_allowed_hosts = vec!["mail.example.gov".into()];
    assert!(config.sovereign_violations().is_empty());

    // An empty S3 endpoint is AWS, and an outside AI key is refused.
    config.storage.s3_endpoint = String::new();
    config.google_ai.api_key = "k".into();
    let fields: Vec<String> = config
        .sovereign_violations()
        .into_iter()
        .map(|(field, _)| field)
        .collect();
    assert_eq!(fields, ["storage.s3_endpoint", "google_ai.api_key"]);
}

#[test]
fn validate_refuses_an_outside_generation_endpoint_unless_allowed() {
    let mut config = minimal_valid_config();
    config.inference.generation.base_url = "https://api.example-ai.com/v1".into();
    let err = config.validate().unwrap_err();
    assert!(
        format!("{err}").contains("inference.generation.base_url"),
        "{err}"
    );
    config.inference.allow_external_provider = true;
    assert!(config.validate().is_ok());
    config.inference.allow_external_provider = false;
    config.inference.generation.base_url = "http://10.1.2.3:8000/v1".into();
    assert!(
        config.validate().is_ok(),
        "a model server on the private network is inside"
    );
}

/// Z1-T2: a password, key or client secret in the config is a `Secret`, never a
/// plain `String`, so it cannot reach a log, a `format!` or a JSON response by
/// accident. Scans the section sources for a field named like a secret.
#[test]
fn no_secret_named_field_is_a_plain_string() {
    let sources = [
        ("audit.rs", include_str!("sections/audit.rs")),
        ("auth.rs", include_str!("sections/auth.rs")),
        ("backup.rs", include_str!("sections/backup.rs")),
        ("cache.rs", include_str!("sections/cache.rs")),
        ("capability.rs", include_str!("sections/capability.rs")),
        ("database.rs", include_str!("sections/database.rs")),
        ("deployment.rs", include_str!("sections/deployment.rs")),
        ("docgen.rs", include_str!("sections/docgen.rs")),
        ("events.rs", include_str!("sections/events.rs")),
        ("fleet.rs", include_str!("sections/fleet.rs")),
        ("inference.rs", include_str!("sections/inference.rs")),
        ("integration.rs", include_str!("sections/integration.rs")),
        ("metadata.rs", include_str!("sections/metadata.rs")),
        (
            "observability.rs",
            include_str!("sections/observability.rs"),
        ),
        ("platform.rs", include_str!("sections/platform.rs")),
        ("portal.rs", include_str!("sections/portal.rs")),
        ("storage.rs", include_str!("sections/storage.rs")),
        ("webchat.rs", include_str!("sections/webchat.rs")),
        ("webcrawl.rs", include_str!("sections/webcrawl.rs")),
    ];
    let secret_words = ["password", "secret", "private_key", "api_key", "pepper"];
    let mut offenders = Vec::new();
    for (file, source) in sources {
        for line in source.lines() {
            let Some(field) = line.trim().strip_prefix("pub ") else {
                continue;
            };
            let Some((name, ty)) = field.split_once(':') else {
                continue;
            };
            let ty = ty.trim().trim_end_matches(',');
            let plain = ty == "String" || ty == "Option<String>";
            if plain && secret_words.iter().any(|w| name.contains(w)) {
                offenders.push(format!("{file}: {}", line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "secret fields must be Secret: {offenders:?}"
    );
}

/// Z1-T5: a production configuration whose secret is typed into the file is
/// refused, naming the path and not the value.
#[test]
fn production_rejects_literal_secret() {
    let mut config = production_ready_config();
    config.validate().expect("the production baseline is valid");
    config.literal_paths = vec!["app.name".into(), "auth.jwt_secret".into()];
    let err = config.validate().expect_err("a literal secret is refused");
    let text = err.to_string();
    assert!(text.contains("auth.jwt_secret"), "{text}");
    assert!(!text.contains("production-jwt-secret"), "{text}");
}

/// Z1-T5: development keeps literal secrets (the shipped template has them).
#[test]
fn debug_allows_literal_secret() {
    let mut config = minimal_valid_config();
    config.literal_paths = vec!["auth.jwt_secret".into(), "database.password".into()];
    config
        .validate()
        .expect("development allows literal secrets");
}

/// Z1-T5: which paths count as secrets.
#[test]
fn secret_paths_cover_key_rings_lists_and_named_providers() {
    use super::helpers::is_secret_path;
    assert!(is_secret_path("auth.jwt_secret"));
    assert!(is_secret_path("auth.jwt_secret.keys[0].secret"));
    assert!(is_secret_path("oidc.providers.entra.client_secret"));
    assert!(is_secret_path("s2s.seeded_clients[2].secret"));
    assert!(is_secret_path("inference.embedding.api_key"));
    assert!(!is_secret_path("auth.jwt_issuer"));
    assert!(!is_secret_path("oidc.providers.entra.client_id"));
    assert!(!is_secret_path("database.user"));
}

/// Z1-T5: the expander lists the strings written as is, by path.
#[test]
fn the_expander_lists_literal_strings_by_path() {
    let mut document = serde_json::json!({
        "auth": { "jwt_secret": "typed-in", "apikey_hash_pepper": "${ATTOME_TEST_Z1T5_UNSET}" },
        "list": [{ "secret": "x" }],
        "_readme": "prose",
        "empty": ""
    });
    let mut unresolved = Vec::new();
    let mut literals = Vec::new();
    super::helpers::expand_env_vars_tracking(&mut document, &mut unresolved, &mut literals);
    literals.sort();
    assert_eq!(literals, ["auth.jwt_secret", "list[0].secret"]);
}

/// Z2-T6: a read replica is a read-only role on its own endpoint; the same
/// endpoint as the primary is no replica, so no read-your-writes pin.
#[test]
fn read_replica_needs_its_own_endpoint() {
    let mut config = minimal_valid_config();
    config.database.readonly = None;
    assert!(!config.database.has_read_replica());
    config.database.readonly =
        Some(serde_json::from_value(serde_json::json!({ "user": "ro", "password": "x" })).unwrap());
    assert!(!config.database.has_read_replica());
    config.database.readonly = Some(
        serde_json::from_value(
            serde_json::json!({ "user": "ro", "password": "x", "host": "replica.internal" }),
        )
        .unwrap(),
    );
    assert!(config.database.has_read_replica());
}

/// AA9-T2: a boot-config limit below its floor refuses to start, naming it.
#[test]
fn boot_rejects_limit_below_floor() {
    let mut config = minimal_valid_config();
    config.auth.mfa_challenge_max_attempts = 0;
    let err = config
        .validate()
        .expect_err("0 attempts is below the floor");
    let text = err.to_string();
    assert!(text.contains("auth.mfa_challenge_max_attempts"), "{text}");
    let mut config = minimal_valid_config();
    config.rate_limit.anonymous_rpm = 0;
    assert!(
        config.validate().is_err(),
        "a rate of 0 switches the limit off"
    );
}

/// Z1-T7: the fingerprint view keeps no secret value, a change of setting
/// changes the fingerprint and a change of secret does not.
#[test]
fn fingerprint_view_has_no_secret_values() {
    use crate::fingerprint::{fingerprint_of, view_of};
    let document = |port: u16, password: &str| {
        serde_json::json!({
            "app": { "port": port },
            "database": {
                "password": password,
                "direct_url": format!("postgres://boot:{password}@db:5432/attome")
            },
            "auth": { "jwt_secret": { "keys": { "k1": password }, "active_key_id": "k1" } },
            "email": { "smtp_password": password, "providers": { "sendgrid": { "api_key": password } } },
            "integration": { "credential_encryption_key": password }
        })
    };
    let sentinel = "SENTINEL-not-in-the-view-4f1c";
    let view = view_of(&document(8080, sentinel));
    assert!(!view.to_string().contains(sentinel), "{view}");
    assert_eq!(
        view["database"]["password"],
        serde_json::json!({ "set": true })
    );
    assert_eq!(view["app"]["port"], 8080);
    let base = fingerprint_of(&view);
    assert_eq!(
        base,
        fingerprint_of(&view_of(&document(8080, "another-secret-value"))),
        "a secret's value does not change the fingerprint"
    );
    assert_ne!(
        base,
        fingerprint_of(&view_of(&document(8081, sentinel))),
        "a setting does"
    );
}
