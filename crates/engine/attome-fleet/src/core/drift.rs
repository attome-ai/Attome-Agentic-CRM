//! Drift detection: does a deployment's last-observed {image digest, schema
//! version, config hash} match what the fleet operator declared as its
//! target? Deliberately a pure comparison over already-collected data —
//! `fleet-migrations::orchestrator::Orchestrator::sync_registry` is what
//! actually calls each deployment and populates `DeploymentRecord::observed`
//! before this runs.

use serde::{Deserialize, Serialize};

use super::ids::DeploymentId;
use super::registry::{DeploymentRecord, FleetRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftField {
    ImageDigest,
    SchemaVersion,
    ConfigHash,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DriftStatus {
    /// No `expected` key was ever declared for this deployment — nothing to
    /// compare against (e.g. freshly registered, pre-first-rollout).
    NoTarget,
    /// No successful probe has ever landed (`observed` is `None`).
    NeverObserved,
    /// The deployment's own last-reported migration state is dirty
    /// (`schema_dirty`) — reported distinctly from `Diverged` because it
    /// means "the deployment itself is in an interrupted state," not "the
    /// fleet declared a different target."
    SchemaDirty,
    /// Every axis that could be confirmed matches the declared target. See
    /// `DriftReport::unconfirmed` for axes that simply couldn't be checked
    /// — `InSync` does not claim those match, only that none are known to
    /// differ.
    InSync,
    /// At least one axis was both observable and confirmed different from
    /// the declared target.
    Diverged { fields: Vec<DriftField> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub deployment_id: DeploymentId,
    pub customer_label: String,
    pub status: DriftStatus,
    /// Axes the last probe could not resolve (see
    /// `crate::registry::ObservedKey`'s doc comment) — kept separate from
    /// `status` so "confirmed in sync" and "in sync on the axes we could
    /// check, unknown on the rest" are never conflated into one signal.
    pub unconfirmed: Vec<DriftField>,
}

pub fn detect_drift(record: &DeploymentRecord) -> DriftReport {
    let base = |status: DriftStatus, unconfirmed: Vec<DriftField>| DriftReport {
        deployment_id: record.id,
        customer_label: record.customer_label.clone(),
        status,
        unconfirmed,
    };

    let Some(expected) = &record.expected else {
        return base(DriftStatus::NoTarget, Vec::new());
    };
    let Some(observed) = &record.observed else {
        return base(DriftStatus::NeverObserved, Vec::new());
    };
    if observed.schema_dirty {
        return base(DriftStatus::SchemaDirty, Vec::new());
    }

    let mut diverged = Vec::new();
    let mut unconfirmed = Vec::new();

    match &observed.key.image_digest {
        Some(d) if *d == expected.image_digest => {}
        Some(_) => diverged.push(DriftField::ImageDigest),
        None => unconfirmed.push(DriftField::ImageDigest),
    }
    match observed.key.schema_version {
        Some(v) if v == expected.schema_version => {}
        Some(_) => diverged.push(DriftField::SchemaVersion),
        None => unconfirmed.push(DriftField::SchemaVersion),
    }
    match &observed.key.config_hash {
        Some(h) if *h == expected.config_hash => {}
        Some(_) => diverged.push(DriftField::ConfigHash),
        None => unconfirmed.push(DriftField::ConfigHash),
    }

    let status = if diverged.is_empty() {
        DriftStatus::InSync
    } else {
        DriftStatus::Diverged { fields: diverged }
    };
    base(status, unconfirmed)
}

/// Sweeps every registered deployment — the primitive `fleetctl drift` (and,
/// eventually, a scheduled fleet-health job) calls.
pub fn sweep(registry: &FleetRegistry) -> Vec<DriftReport> {
    registry.list().map(detect_drift).collect()
}

#[cfg(test)]
mod tests {
    use super::super::ids::{ConfigHash, ImageDigest, SchemaVersion};
    use super::super::registry::{DeploymentRecord, FleetKey, ObservedKey, ObservedState};
    use super::*;
    use chrono::Utc;

    fn key(digest_byte: char, schema: i64, cfg: &str) -> FleetKey {
        FleetKey {
            image_digest: ImageDigest::parse(format!(
                "sha256:{}",
                digest_byte.to_string().repeat(64)
            ))
            .unwrap(),
            schema_version: SchemaVersion(schema),
            config_hash: ConfigHash::new(cfg),
        }
    }

    #[test]
    fn no_expected_target_is_no_target() {
        let record = DeploymentRecord::new("acme", "https://acme.example.com");
        assert_eq!(detect_drift(&record).status, DriftStatus::NoTarget);
    }

    #[test]
    fn expected_without_observation_is_never_observed() {
        let mut record = DeploymentRecord::new("acme", "https://acme.example.com");
        record.expected = Some(key('a', 1, "cfg"));
        assert_eq!(detect_drift(&record).status, DriftStatus::NeverObserved);
    }

    #[test]
    fn fully_confirmed_match_is_in_sync_with_nothing_unconfirmed() {
        let mut record = DeploymentRecord::new("acme", "https://acme.example.com");
        let target = key('a', 1, "cfg");
        record.expected = Some(target.clone());
        record.observed = Some(ObservedState {
            key: ObservedKey {
                image_digest: Some(target.image_digest.clone()),
                schema_version: Some(target.schema_version),
                config_hash: Some(target.config_hash.clone()),
            },
            application_version: "4.0.1".into(),
            git_revision: "abc123".into(),
            schema_dirty: false,
            ready: true,
            observed_at: Utc::now(),
        });
        let report = detect_drift(&record);
        assert_eq!(report.status, DriftStatus::InSync);
        assert!(report.unconfirmed.is_empty());
    }

    #[test]
    fn unresolved_image_digest_is_unconfirmed_not_diverged() {
        let mut record = DeploymentRecord::new("acme", "https://acme.example.com");
        let target = key('a', 1, "cfg");
        record.expected = Some(target.clone());
        record.observed = Some(ObservedState {
            key: ObservedKey {
                image_digest: None, // could not resolve via the manifest lookup
                schema_version: Some(target.schema_version),
                config_hash: None, // never reported by any deployment today
            },
            application_version: "4.0.1".into(),
            git_revision: "abc123".into(),
            schema_dirty: false,
            ready: true,
            observed_at: Utc::now(),
        });
        let report = detect_drift(&record);
        assert_eq!(report.status, DriftStatus::InSync);
        assert_eq!(
            report.unconfirmed,
            vec![DriftField::ImageDigest, DriftField::ConfigHash]
        );
    }

    #[test]
    fn mismatched_schema_version_is_diverged() {
        let mut record = DeploymentRecord::new("acme", "https://acme.example.com");
        let target = key('a', 5, "cfg");
        record.expected = Some(target.clone());
        record.observed = Some(ObservedState {
            key: ObservedKey {
                image_digest: Some(target.image_digest.clone()),
                schema_version: Some(SchemaVersion(4)), // stale, one behind the fleet's declared target
                config_hash: Some(target.config_hash.clone()),
            },
            application_version: "4.0.0".into(),
            git_revision: "def456".into(),
            schema_dirty: false,
            ready: true,
            observed_at: Utc::now(),
        });
        let report = detect_drift(&record);
        assert_eq!(
            report.status,
            DriftStatus::Diverged {
                fields: vec![DriftField::SchemaVersion]
            }
        );
    }

    #[test]
    fn dirty_schema_is_reported_distinctly_from_divergence() {
        let mut record = DeploymentRecord::new("acme", "https://acme.example.com");
        let target = key('a', 5, "cfg");
        record.expected = Some(target.clone());
        record.observed = Some(ObservedState {
            key: ObservedKey {
                image_digest: Some(target.image_digest.clone()),
                schema_version: Some(target.schema_version),
                config_hash: Some(target.config_hash.clone()),
            },
            application_version: "4.0.1".into(),
            git_revision: "abc123".into(),
            schema_dirty: true,
            ready: false,
            observed_at: Utc::now(),
        });
        assert_eq!(detect_drift(&record).status, DriftStatus::SchemaDirty);
    }
}
