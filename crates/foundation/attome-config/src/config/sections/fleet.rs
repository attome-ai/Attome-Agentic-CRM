//! D-792 — the fleet console's configuration (FLEET-CONSOLE-DESIGN.md §2.1).
//! Plain data only (BCF-14): `xrm-fleet` reads these fields off
//! `AppConfig.fleet`, and only when its four-lock gate is open.
//!
//! The section is optional and empty by default, so every existing config
//! file stays valid. It belongs on the developer's own machine only: a
//! non-default `fleet` section on `app.deployment_profile = "production"` is
//! a boot error (`AppConfig::validate_production_profile`), because a
//! production server must never carry the fleet key.
//!
//! `credential_encryption_key` is its own [`KeyRing`], a separate trust
//! domain from every other ring (D-069): it encrypts each customer's rollout
//! S2S secret at rest (`xrm_fleet_deployment.secret_enc`) and nothing else.
use crate::keyring::KeyRing;
use serde::Deserialize;
use uuid::Uuid;

/// Default poll cadence: every 15 minutes (design §6.3).
pub(crate) const DEFAULT_POLL_INTERVAL_SECS: u64 = 900;
/// Default per-request timeout towards a customer server (design §6.1).
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
/// Default changeset directory, relative to the working directory (design §9 Q3).
pub(crate) const DEFAULT_CHANGESETS_DIR: &str = "changesets";

const POLL_INTERVAL_RANGE: std::ops::RangeInclusive<u64> = 60..=86_400;
const REQUEST_TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=120;

/// Hand-written: `credential_encryption_key` holds key material. `KeyRing`'s
/// own `Debug` already redacts its values; this impl keeps the section's
/// redaction explicit, like every other secret-bearing section (BCF-1).
impl std::fmt::Debug for FleetSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetSection")
            .field("credential_encryption_key", &self.credential_encryption_key)
            .field("poll_interval_secs", &self.poll_interval_secs)
            .field("changesets_dir", &self.changesets_dir)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("notify_user_refs", &self.notify_user_refs)
            .finish()
    }
}

#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct FleetSection {
    /// Encrypts each customer's rollout S2S secret at rest. Required (and
    /// checked) only when the console is requested with
    /// `ATTOME_FLEET_CONSOLE=1`; well formed whenever it is set.
    pub credential_encryption_key: KeyRing,
    /// How often the gated `FleetPoll` scheduler syncs every customer.
    pub poll_interval_secs: u64,
    /// Where closed `attome-changeset/v1` files are read from (the developer
    /// runs the source tree, design §6.4).
    pub changesets_dir: String,
    /// Bound on one outbound call to a customer server.
    pub request_timeout_secs: u64,
    /// Who the F3 notifications go to. Empty: every active `system.admin`
    /// holder of the developer's database.
    pub notify_user_refs: Vec<Uuid>,
}

impl Default for FleetSection {
    fn default() -> Self {
        Self {
            credential_encryption_key: KeyRing::default(),
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            changesets_dir: DEFAULT_CHANGESETS_DIR.to_string(),
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            notify_user_refs: Vec::new(),
        }
    }
}

impl FleetSection {
    /// True when any field differs from its default — what the production
    /// profile refuses (design §2.3, last row).
    pub fn is_configured(&self) -> bool {
        !self.credential_encryption_key.is_empty()
            || self.poll_interval_secs != DEFAULT_POLL_INTERVAL_SECS
            || self.changesets_dir != DEFAULT_CHANGESETS_DIR
            || self.request_timeout_secs != DEFAULT_REQUEST_TIMEOUT_SECS
            || !self.notify_user_refs.is_empty()
    }

    /// Shape check run by `AppConfig::validate` in every profile. Returns the
    /// offending field and the reason. The key ring's own checks
    /// (`check_secret_ring`, `check_hex_key_ring`) run in `loader.rs`, next to
    /// every other ring's.
    pub fn check(&self) -> Result<(), (String, String)> {
        if !POLL_INTERVAL_RANGE.contains(&self.poll_interval_secs) {
            return Err((
                "fleet.poll_interval_secs".into(),
                format!(
                    "must be between {} and {} seconds, got {}",
                    POLL_INTERVAL_RANGE.start(),
                    POLL_INTERVAL_RANGE.end(),
                    self.poll_interval_secs
                ),
            ));
        }
        if !REQUEST_TIMEOUT_RANGE.contains(&self.request_timeout_secs) {
            return Err((
                "fleet.request_timeout_secs".into(),
                format!(
                    "must be between {} and {} seconds, got {}",
                    REQUEST_TIMEOUT_RANGE.start(),
                    REQUEST_TIMEOUT_RANGE.end(),
                    self.request_timeout_secs
                ),
            ));
        }
        if self.changesets_dir.trim().is_empty() {
            return Err((
                "fleet.changesets_dir".into(),
                "must not be empty (default \"changesets\")".into(),
            ));
        }
        Ok(())
    }

    /// The production-profile refusal (design §2.3): `Some((field, reason))`
    /// when this section carries anything at all.
    pub fn production_refusal(&self) -> Option<(String, String)> {
        if !self.is_configured() {
            return None;
        }
        let field = if self.credential_encryption_key.is_empty() {
            "fleet"
        } else {
            "fleet.credential_encryption_key"
        };
        Some((
            field.into(),
            "must be absent when app.deployment_profile = \"production\" — the fleet console \
             (D-792) runs only on the developer's own debug build, and a production server must \
             never carry the fleet key or its settings; remove the `fleet` section"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> KeyRing {
        KeyRing::single("ab".repeat(32))
    }

    #[test]
    fn the_default_section_is_unconfigured_and_valid() {
        let section = FleetSection::default();
        assert!(!section.is_configured());
        assert!(section.check().is_ok());
        assert!(section.production_refusal().is_none());
    }

    #[test]
    fn an_absent_section_deserializes_to_the_default() {
        let section: FleetSection = serde_json::from_str("{}").expect("empty object");
        assert!(!section.is_configured());
        assert_eq!(section.poll_interval_secs, 900);
        assert_eq!(section.changesets_dir, "changesets");
        assert_eq!(section.request_timeout_secs, 10);
    }

    #[test]
    fn a_key_alone_makes_the_section_configured_and_refused_on_production() {
        let section = FleetSection {
            credential_encryption_key: ring(),
            ..FleetSection::default()
        };
        assert!(section.is_configured());
        let (field, reason) = section.production_refusal().expect("refused");
        assert_eq!(field, "fleet.credential_encryption_key");
        assert!(reason.contains("production"));
    }

    #[test]
    fn any_non_default_setting_is_refused_on_production() {
        let section = FleetSection {
            poll_interval_secs: 600,
            ..FleetSection::default()
        };
        assert_eq!(
            section.production_refusal().map(|(field, _)| field),
            Some("fleet".to_string())
        );
    }

    #[test]
    fn out_of_range_intervals_and_an_empty_dir_are_rejected() {
        let too_fast = FleetSection {
            poll_interval_secs: 10,
            ..FleetSection::default()
        };
        assert_eq!(too_fast.check().unwrap_err().0, "fleet.poll_interval_secs");
        let no_timeout = FleetSection {
            request_timeout_secs: 0,
            ..FleetSection::default()
        };
        assert_eq!(
            no_timeout.check().unwrap_err().0,
            "fleet.request_timeout_secs"
        );
        let no_dir = FleetSection {
            changesets_dir: "  ".into(),
            ..FleetSection::default()
        };
        assert_eq!(no_dir.check().unwrap_err().0, "fleet.changesets_dir");
    }

    #[test]
    fn debug_never_prints_the_key() {
        let section = FleetSection {
            credential_encryption_key: ring(),
            ..FleetSection::default()
        };
        assert!(!format!("{section:?}").contains(&"ab".repeat(32)));
    }
}
