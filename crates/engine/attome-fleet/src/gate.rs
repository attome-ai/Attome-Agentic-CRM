//! The four-lock gate (D-792 rule 1, FLEET-CONSOLE-DESIGN.md §2).
//!
//! Locks 1 and 2 are compile-time facts this crate cannot see from inside:
//! the code exists only when `crates/server` is built with the non-default
//! `fleet-console` feature, and a `compile_error!` there refuses that feature
//! in a release build. This module holds locks 3 and 4 plus the key check:
//! `ATTOME_FLEET_CONSOLE=1`, `APP_ENV=debug`, `app.deployment_profile =
//! "development"` and a usable `fleet.credential_encryption_key`.
//!
//! A half-open gate is an error, not a warning (§2.3): the variable set on a
//! production profile, without `APP_ENV=debug`, or without the key refuses
//! boot. The variable unset (or anything but exactly `"1"`) is simply off.
//!
//! The decision is a pure function of [`GateInputs`] and the config, so every
//! §2.3 row is a unit test and the server's boot, scheduler and job paths all
//! reach the same answer.

use attome_config::AppConfig;

/// The owner's switch (design §2.1). Only the exact value `"1"` opens it.
pub const ENV_VAR: &str = "ATTOME_FLEET_CONSOLE";

/// The process facts the gate reads, captured once so tests can supply them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateInputs {
    /// `APP_ENV=debug` (`attome_config::is_debug_env`).
    pub app_env_debug: bool,
    /// The raw value of [`ENV_VAR`], if set.
    pub console_var: Option<String>,
}

impl GateInputs {
    /// Reads the live process environment.
    pub fn from_process() -> Self {
        Self {
            app_env_debug: attome_config::is_debug_env(),
            console_var: std::env::var(ENV_VAR).ok(),
        }
    }

    fn requested(&self) -> bool {
        self.console_var.as_deref() == Some("1")
    }
}

/// The gate's answer for this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// No routes, no sidebar group, no jobs, no key use.
    Off,
    /// Every lock holds.
    Open,
}

impl Gate {
    pub fn is_open(self) -> bool {
        self == Gate::Open
    }

    /// The gate a boot already decided (`server::boot::Boot::fleet_console_open`).
    pub fn from_open(open: bool) -> Self {
        if open { Gate::Open } else { Gate::Off }
    }
}

/// A half-open gate: the console was requested but a lock is missing. Each
/// is a boot error (design §2.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    #[error(
        "fleet console requested on a production-profile deployment \
         (ATTOME_FLEET_CONSOLE=1 with app.deployment_profile = \"{0}\"); the console runs only \
         on a development profile (D-792)"
    )]
    NotDevelopmentProfile(String),
    #[error(
        "fleet console requested (ATTOME_FLEET_CONSOLE=1) but APP_ENV is not \"debug\"; the \
         console runs only on the developer's debug server (D-792)"
    )]
    NotDebugEnv,
    #[error(
        "fleet console requested (ATTOME_FLEET_CONSOLE=1) but fleet.credential_encryption_key \
         is not set or its active key is missing; set it to \"${{ATTOME_FLEET_KEY}}\" (64 hex) \
         in the fleet section (D-792)"
    )]
    MissingKey,
}

/// The gate decision (design §2.1, §2.3).
pub fn evaluate(inputs: &GateInputs, config: &AppConfig) -> Result<Gate, GateError> {
    if !inputs.requested() {
        return Ok(Gate::Off);
    }
    if config.app.deployment_profile != "development" {
        return Err(GateError::NotDevelopmentProfile(
            config.app.deployment_profile.clone(),
        ));
    }
    if !inputs.app_env_debug {
        return Err(GateError::NotDebugEnv);
    }
    let ring = &config.fleet.credential_encryption_key;
    if ring.is_empty() || ring.active().is_none() {
        return Err(GateError::MissingKey);
    }
    Ok(Gate::Open)
}

/// [`evaluate`] against the live process environment.
pub fn open(config: &AppConfig) -> Result<Gate, GateError> {
    evaluate(&GateInputs::from_process(), config)
}

/// Fails closed for a job or a scheduler that finds the gate not open: the
/// rows exist on every database (migration 0543), so a job enqueued while
/// the console was open must not act after it was switched off.
pub fn require_open(config: &AppConfig) -> Result<(), attome_types::AppError> {
    match open(config) {
        Ok(Gate::Open) => Ok(()),
        Ok(Gate::Off) => Err(attome_types::AppError::Internal(
            "the fleet console is off in this process (ATTOME_FLEET_CONSOLE is not \"1\"); \
             fleet jobs do not run"
                .into(),
        )),
        Err(e) => Err(attome_types::AppError::Internal(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_config::KeyRing;

    fn config(profile: &str, key: Option<KeyRing>) -> AppConfig {
        let mut document = serde_json::json!({
            "app": {
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "deployment_profile": profile
            },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1, "timeout": 5.0
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
                "metrics_port": 0, "trace_sampling_rate": 1.0, "enable_distributed_tracing": false
            },
            "email": {
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "", "smtp_password": "",
                "smtp_from_address": "a@b.c", "smtp_from_name": "t", "smtp_use_tls": false
            },
            "google_ai": { "api_key": "test" }
        });
        let mut config: AppConfig = match serde_json::from_value(document.take()) {
            Ok(config) => config,
            Err(e) => panic!("the minimal test config must deserialize: {e}"),
        };
        if let Some(ring) = key {
            config.fleet.credential_encryption_key = ring;
        }
        config
    }

    fn key() -> Option<KeyRing> {
        Some(KeyRing::single("cd".repeat(32)))
    }

    fn inputs(debug: bool, var: Option<&str>) -> GateInputs {
        GateInputs {
            app_env_debug: debug,
            console_var: var.map(str::to_owned),
        }
    }

    #[test]
    fn unset_variable_is_off_whatever_else_holds() {
        assert_eq!(
            evaluate(&inputs(true, None), &config("development", key())),
            Ok(Gate::Off)
        );
        assert_eq!(
            evaluate(&inputs(false, None), &config("production", None)),
            Ok(Gate::Off)
        );
    }

    #[test]
    fn a_value_other_than_exactly_one_is_off() {
        for value in ["0", "true", "yes", " 1", "1 ", ""] {
            assert_eq!(
                evaluate(&inputs(true, Some(value)), &config("development", key())),
                Ok(Gate::Off),
                "{value:?}"
            );
        }
    }

    #[test]
    fn requested_on_a_production_profile_refuses_boot() {
        assert_eq!(
            evaluate(&inputs(true, Some("1")), &config("production", key())),
            Err(GateError::NotDevelopmentProfile("production".into()))
        );
    }

    #[test]
    fn requested_without_app_env_debug_refuses_boot() {
        assert_eq!(
            evaluate(&inputs(false, Some("1")), &config("development", key())),
            Err(GateError::NotDebugEnv)
        );
    }

    #[test]
    fn requested_without_the_key_refuses_boot_naming_it() {
        let refused = evaluate(&inputs(true, Some("1")), &config("development", None));
        assert_eq!(refused, Err(GateError::MissingKey));
        let message = GateError::MissingKey.to_string();
        assert!(
            message.contains("fleet.credential_encryption_key"),
            "{message}"
        );
    }

    #[test]
    fn a_ring_whose_active_key_is_missing_counts_as_no_key() {
        let mut ring = KeyRing::single("cd".repeat(32));
        ring.active_key_id = "absent".into();
        assert_eq!(
            evaluate(&inputs(true, Some("1")), &config("development", Some(ring))),
            Err(GateError::MissingKey)
        );
    }

    #[test]
    fn every_lock_holding_opens_the_console() {
        let gate = evaluate(&inputs(true, Some("1")), &config("development", key()));
        assert_eq!(gate, Ok(Gate::Open));
        assert!(gate.is_ok_and(Gate::is_open));
    }
}
