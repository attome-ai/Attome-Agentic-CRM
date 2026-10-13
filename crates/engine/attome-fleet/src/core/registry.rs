//! The fleet deployment registry — fleet-core's answer to "who is running
//! what." Pure in-memory data + logic; `fleet-migrations` owns the actual
//! polling/persistence I/O (see that crate's `client`/`store` modules).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::error::FleetError;
use super::ids::{ConfigHash, DeploymentId, ImageDigest, SchemaVersion};

/// The composite key `P-fleet-control-plane.md`'s registry is keyed on:
/// {image digest, schema version, config hash}. Two deployments sharing an
/// identical `FleetKey` are running byte-identical code against an
/// identically-shaped schema with an identical configuration fingerprint —
/// this is the unit `crate::drift` and `crate::rollout` reason about.
///
/// Every field is required here — this type represents a fully-specified
/// TARGET (what an operator declared, via `fleetctl register`/`fleetctl
/// rollout plan`), not a partial observation. See `ObservedKey` for the
/// weaker, best-effort shape a real probe actually produces.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FleetKey {
    pub image_digest: ImageDigest,
    pub schema_version: SchemaVersion,
    pub config_hash: ConfigHash,
}

/// A best-effort echo of `FleetKey`'s three axes, produced from one real
/// probe. Every field is `Option` because a probe can only ever confirm
/// what it could actually observe:
///
/// - `schema_version` comes straight from `GET /version`'s own
///   `schema_version` field — `None` only on a schema-less fresh boot.
/// - `image_digest` requires a second hop (`fleet-migrations::manifest`
///   resolving the reported `application_version` tag's release manifest)
///   that may not be possible at all — no network egress, private repo, or
///   a version predating `P-deployment-manifest.md`. `None` here means
///   "could not confirm," never "confirmed absent."
/// - `config_hash` is `None` for every deployment today — see
///   `crate::ids::ConfigHash`'s doc comment for why nothing computes one
///   yet.
///
/// `crate::drift::detect_drift` treats a `None` field as "unconfirmed," a
/// distinct outcome from "confirmed different" — never silently promoted to
/// either "in sync" or "diverged."
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedKey {
    pub image_digest: Option<ImageDigest>,
    pub schema_version: Option<SchemaVersion>,
    pub config_hash: Option<ConfigHash>,
}

/// The full result of one successful probe against a deployment's
/// `/version`/`/health/ready` endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedState {
    pub key: ObservedKey,
    pub application_version: String,
    pub git_revision: String,
    pub schema_dirty: bool,
    /// `GET /health/ready`'s status code — `true` only on a 2xx.
    pub ready: bool,
    pub observed_at: DateTime<Utc>,
}

/// One customer deployment's registry entry. `expected` is the fleet
/// operator's declared target (set by `fleetctl register` / `fleetctl
/// rollout plan`); `observed` is the last real signal a probe actually
/// returned, or `None` before the first successful sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub id: DeploymentId,
    pub customer_label: String,
    /// Base URL `fleet-migrations` polls `GET {endpoint}/version` and
    /// `GET {endpoint}/health/ready` against — never anything beyond that
    /// unauthenticated, read-only pair (`P-fleet-control-plane.md` §6's
    /// boundary invariant: the fleet control plane is a privileged client
    /// of deployments, never a component running inside them).
    pub endpoint: String,
    pub expected: Option<FleetKey>,
    pub observed: Option<ObservedState>,
    pub registered_at: DateTime<Utc>,
}

impl DeploymentRecord {
    pub fn new(customer_label: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            id: DeploymentId::new(),
            customer_label: customer_label.into(),
            endpoint: endpoint.into(),
            expected: None,
            observed: None,
            registered_at: Utc::now(),
        }
    }
}

/// In-memory fleet registry, serde round-trippable so `fleet-migrations`'s
/// `store` module can persist it to a local JSON file between `fleetctl`
/// invocations. There is deliberately no fleet-owned database here — see
/// `attome-fleet/README.md` for why a local file is the right size of
/// solution for this prototype stage, and D-002 for why it could never hold
/// customer business data even if it were one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetRegistry {
    deployments: BTreeMap<DeploymentId, DeploymentRecord>,
}

impl FleetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, record: DeploymentRecord) -> Result<(), FleetError> {
        if self.deployments.contains_key(&record.id) {
            return Err(FleetError::DuplicateDeployment(record.id));
        }
        self.deployments.insert(record.id, record);
        Ok(())
    }

    pub fn get(&self, id: DeploymentId) -> Result<&DeploymentRecord, FleetError> {
        self.deployments
            .get(&id)
            .ok_or(FleetError::UnknownDeployment(id))
    }

    pub fn get_mut(&mut self, id: DeploymentId) -> Result<&mut DeploymentRecord, FleetError> {
        self.deployments
            .get_mut(&id)
            .ok_or(FleetError::UnknownDeployment(id))
    }

    pub fn remove(&mut self, id: DeploymentId) -> Result<DeploymentRecord, FleetError> {
        self.deployments
            .remove(&id)
            .ok_or(FleetError::UnknownDeployment(id))
    }

    pub fn list(&self) -> impl Iterator<Item = &DeploymentRecord> {
        self.deployments.values()
    }

    pub fn len(&self) -> usize {
        self.deployments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deployments.is_empty()
    }

    pub fn set_expected(&mut self, id: DeploymentId, target: FleetKey) -> Result<(), FleetError> {
        self.get_mut(id)?.expected = Some(target);
        Ok(())
    }

    pub fn record_observation(
        &mut self,
        id: DeploymentId,
        observed: ObservedState,
    ) -> Result<(), FleetError> {
        self.get_mut(id)?.observed = Some(observed);
        Ok(())
    }

    /// All deployments whose declared target matches `key` — the group a
    /// rollout wave or drift sweep acts on.
    pub fn matching_expected(&self, key: &FleetKey) -> Vec<DeploymentId> {
        self.deployments
            .values()
            .filter(|r| r.expected.as_ref() == Some(key))
            .map(|r| r.id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(digest_byte: char, schema: i64) -> FleetKey {
        FleetKey {
            image_digest: ImageDigest::parse(format!(
                "sha256:{}",
                digest_byte.to_string().repeat(64)
            ))
            .unwrap(),
            schema_version: SchemaVersion(schema),
            config_hash: ConfigHash::new("cfg-1"),
        }
    }

    #[test]
    fn register_then_get_round_trips() {
        let mut registry = FleetRegistry::new();
        let record = DeploymentRecord::new("acme", "https://acme.example.com");
        let id = record.id;
        registry.register(record).unwrap();
        assert_eq!(registry.get(id).unwrap().customer_label, "acme");
    }

    #[test]
    fn duplicate_register_is_rejected() {
        let mut registry = FleetRegistry::new();
        let mut record = DeploymentRecord::new("acme", "https://acme.example.com");
        record.id = DeploymentId::new();
        let dup = DeploymentRecord {
            id: record.id,
            ..DeploymentRecord::new("acme-2", "https://acme2.example.com")
        };
        registry.register(record).unwrap();
        assert!(matches!(
            registry.register(dup),
            Err(FleetError::DuplicateDeployment(_))
        ));
    }

    #[test]
    fn unknown_deployment_lookups_error() {
        let registry = FleetRegistry::new();
        assert!(matches!(
            registry.get(DeploymentId::new()),
            Err(FleetError::UnknownDeployment(_))
        ));
    }

    #[test]
    fn matching_expected_filters_by_declared_target() {
        let mut registry = FleetRegistry::new();
        let a = DeploymentRecord::new("a", "https://a.example.com");
        let b = DeploymentRecord::new("b", "https://b.example.com");
        let (a_id, b_id) = (a.id, b.id);
        registry.register(a).unwrap();
        registry.register(b).unwrap();

        let target = key('a', 5);
        registry.set_expected(a_id, target.clone()).unwrap();
        registry.set_expected(b_id, key('b', 5)).unwrap();

        assert_eq!(registry.matching_expected(&target), vec![a_id]);
    }
}
