//! Identity and key primitives shared by every `fleet-core` module.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::FleetError;

/// Identifies one customer deployment in the fleet registry. This id exists
/// only in the fleet control plane's own bookkeeping — distinct from, and
/// never sent to or accepted from, any deployment's own primary keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeploymentId(pub Uuid);

impl DeploymentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn parse(raw: &str) -> Result<Self, FleetError> {
        Uuid::parse_str(raw)
            .map(Self)
            .map_err(|_| FleetError::InvalidDeploymentId(raw.to_string()))
    }
}

impl Default for DeploymentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DeploymentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A container image's registry digest (`sha256:<64 lowercase hex chars>`)
/// — the release-time half of `deployment-manifest.json`
/// (`images.server.digest`, `document/detailed-plans/P-deployment-manifest.md`
/// §4). Never observable from a running process: `GET /version`
/// deliberately omits it, because a process cannot know its own image's
/// registry digest (the registry computes it from the pushed layers, after
/// the binary inside already started — same doc, same section). The fleet
/// control plane learns a deployment's digest one of two ways: an operator
/// records it directly (`fleetctl register --image-digest`), or
/// `fleet-migrations::manifest` resolves it from the matching release's
/// published `deployment-manifest.json` — see that module for the (TODO:
/// unverified, needs live network egress) GitHub Releases lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn parse(raw: impl Into<String>) -> Result<Self, FleetError> {
        let raw = raw.into();
        let valid = raw
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        if valid {
            Ok(Self(raw))
        } else {
            Err(FleetError::InvalidImageDigest(raw))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The highest applied migration ordinal — the exact value
/// `attome_db::schema_state` reports as `applied_max_version` and `GET
/// /version` reports as `schema_version`
/// (`crates/foundation/attome-server/src/health.rs`). Reused directly, not
/// redefined: both are `i64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaVersion(pub i64);

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A fingerprint of one deployment's effective configuration, computed and
/// self-reported BY that deployment — never derived by the fleet control
/// plane from raw config, and never transmitted in full. Raw `AppConfig`
/// carries JWT secrets, DB passwords, and S2S keys
/// (`P-deployment-manifest.md` §4's "hash the entire effective AppConfig"
/// rejection applies with even more force to a value that would leave the
/// deployment's own network boundary).
///
/// As of P-environment-promotion §5 step 20, `GET /version`'s
/// `configuration_version` IS this: the sha256 of the deployment's canonical
/// metadata export (`attome_api::bundle::canonical::bundle_hash`), computed
/// by the deployment itself at boot and again after every successful bundle
/// apply — not a masked/salted config hash (raw `AppConfig` never leaves the
/// deployment's boundary, `P-deployment-manifest.md` §4's rejection still
/// applies to that), and no longer just `application_version` (the old
/// D-211 posture). `fleetctl sync`/`drift`, which already compare
/// `ConfigHash` on every poll, are therefore the scheduled drift check for
/// configuration metadata — no scheduler runs inside the deployment.
/// `fleetctl register --config-hash` still accepts an operator-supplied
/// value (a deployment on an older binary has no such field to probe, and
/// falls back to `application_version`) — see
/// `fleet_core::registry::ObservedKey`'s doc comment for how drift detection
/// accounts for that mixed provenance honestly rather than fabricating a
/// signal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConfigHash(String);

impl ConfigHash {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_digest_accepts_well_formed_sha256() {
        let digest = "sha256:".to_string() + &"a".repeat(64);
        assert!(ImageDigest::parse(digest).is_ok());
    }

    #[test]
    fn image_digest_rejects_wrong_length() {
        let digest = "sha256:".to_string() + &"a".repeat(63);
        assert!(ImageDigest::parse(digest).is_err());
    }

    #[test]
    fn image_digest_rejects_missing_prefix() {
        assert!(ImageDigest::parse("a".repeat(64)).is_err());
    }

    #[test]
    fn image_digest_rejects_non_hex() {
        let digest = "sha256:".to_string() + &"g".repeat(64);
        assert!(ImageDigest::parse(digest).is_err());
    }

    #[test]
    fn deployment_id_round_trips_through_display_and_parse() {
        let id = DeploymentId::new();
        let parsed = DeploymentId::parse(&id.to_string()).unwrap();
        assert_eq!(id, parsed);
    }
}
