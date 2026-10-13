//! Pure domain types and logic for the Attome fleet control plane — moved
//! here from `attome-fleet/crates/fleet-core` (D-792, FLEET-CONSOLE-DESIGN.md
//! §3.2) with its unit tests. Zero I/O by design: every type and function here
//! is deterministic and unit-testable without a network, filesystem, database,
//! or live deployment. The rest of `attome-fleet` (`client`, `store`, `publish`,
//! `poll`) performs the I/O on top of these types.
//!
//! Every path between these files is `super::`-relative, never `crate::` (a
//! leftover of the transition, when this directory was also the root of the
//! legacy `fleet-core` package; lane FC-D retired `attome-fleet/`, design §3.2).

pub mod drift;
pub mod error;
pub mod ids;
pub mod registry;
pub mod rollout;
pub mod version_probe;

pub use drift::{DriftField, DriftReport, DriftStatus, detect_drift, sweep};
pub use error::FleetError;
pub use ids::{ConfigHash, DeploymentId, ImageDigest, SchemaVersion};
pub use registry::{DeploymentRecord, FleetKey, FleetRegistry, ObservedKey, ObservedState};
pub use rollout::{
    RolloutPlan, RolloutStatus, RolloutWave, WaveState, plan_waves, plan_waves_by_groups,
};
pub use version_probe::VersionProbe;
