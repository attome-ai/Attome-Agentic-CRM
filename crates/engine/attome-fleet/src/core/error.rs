use thiserror::Error;

use super::ids::DeploymentId;

/// Every error `fleet-core`'s pure logic can produce. No I/O error variant
/// lives here — network/filesystem failures belong to `fleet-migrations`
/// (`ProbeError`, `StoreError`, `ManifestError`), which is the only crate in
/// this workspace that performs I/O.
#[derive(Debug, Error)]
pub enum FleetError {
    #[error("invalid image digest {0:?}: expected \"sha256:\" followed by 64 lowercase hex chars")]
    InvalidImageDigest(String),

    #[error("{0:?} is not a valid deployment id (expected a UUID)")]
    InvalidDeploymentId(String),

    #[error("deployment {0} is not registered")]
    UnknownDeployment(DeploymentId),

    #[error("deployment {0} is already registered")]
    DuplicateDeployment(DeploymentId),

    #[error("invalid rollout plan: {0}")]
    InvalidRolloutPlan(String),

    #[error("cannot {attempted}: rollout is currently {current}")]
    InvalidRolloutTransition { attempted: String, current: String },
}
