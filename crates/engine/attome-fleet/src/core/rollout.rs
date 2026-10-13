//! Progressive rollout: promote a fleet, wave by wave, toward a declared
//! `FleetKey` target — the state machine behind "one command that rolls a
//! version across the fleet" (`fleetctl rollout run`). Pure here;
//! `fleet-migrations::orchestrator::Orchestrator::run_rollout` is the async
//! driver that actually polls deployment health and calls these
//! transitions — see that module's doc comment for exactly what it does
//! and does not do (it recognizes a wave has already been upgraded and
//! gates promotion on that; it does not trigger the upgrade itself).
//!
//! Modeled after the canary -> percentage -> 100% pattern
//! `P-fleet-control-plane.md` §4(c) names (Argo Rollouts / Flagger):
//! automatic promotion while health stays green, automatic halt on
//! regression, a human paged only on failure rather than gating every
//! promotion on one.

use serde::{Deserialize, Serialize};

use super::error::FleetError;
use super::ids::DeploymentId;
use super::registry::FleetKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WaveState {
    Pending,
    InProgress,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutWave {
    pub name: String,
    pub deployments: Vec<DeploymentId>,
    /// Number of this wave's deployments allowed to fail the health gate
    /// before the wave — and the whole rollout — halts. Defaults to 0
    /// ("any single failure halts") in `plan_waves`, the correct default
    /// for a fleet this small; a larger fleet would widen this per wave.
    pub max_unhealthy: usize,
    pub state: WaveState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RolloutStatus {
    Planned,
    InProgress,
    Completed,
    Halted,
    RolledBack,
}

/// Generic over what the waves converge to (D-792): `FleetKey` (the default,
/// `fleetctl`'s image/schema/config target) or the fleet console's release
/// of changesets (`attome_fleet::publish::ReleaseTarget`). The state machine
/// never reads `target`; it only carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutPlan<T = FleetKey> {
    pub target: T,
    pub waves: Vec<RolloutWave>,
    /// Index into `waves` of the wave currently active, or next to start.
    pub cursor: usize,
    pub status: RolloutStatus,
}

/// Splits `deployments` into waves by percentage (e.g. `[10, 50, 100]` means
/// "canary 10%, then 50% cumulative, then the rest") — the shape
/// `P-fleet-control-plane.md` §4(c) names. Each percentage is of the TOTAL
/// fleet, cumulative, and the last entry must be exactly 100 (rejected, not
/// silently corrected, if it isn't) so no deployment is ever silently
/// excluded from every wave. Percentages must be strictly increasing, and
/// there must be no more waves than deployments (otherwise a wave would get
/// zero deployments, which `plan_waves` refuses to produce rather than
/// silently allow an empty wave through the state machine).
pub fn plan_waves<T>(
    target: T,
    deployments: &[DeploymentId],
    percentages: &[u8],
) -> Result<RolloutPlan<T>, FleetError> {
    if deployments.is_empty() {
        return Err(FleetError::InvalidRolloutPlan(
            "no deployments to roll out to".into(),
        ));
    }
    if percentages.is_empty() {
        return Err(FleetError::InvalidRolloutPlan(
            "no wave percentages given".into(),
        ));
    }
    if percentages.last() != Some(&100) {
        return Err(FleetError::InvalidRolloutPlan(format!(
            "last wave must cover 100% of the fleet, got {percentages:?}"
        )));
    }
    let mut prev = 0u8;
    for &p in percentages {
        if p <= prev || p > 100 {
            return Err(FleetError::InvalidRolloutPlan(format!(
                "wave percentages must be strictly increasing and <=100, got {percentages:?}"
            )));
        }
        prev = p;
    }
    if percentages.len() > deployments.len() {
        return Err(FleetError::InvalidRolloutPlan(format!(
            "cannot split {} deployment(s) into {} waves — each wave needs at least one",
            deployments.len(),
            percentages.len()
        )));
    }

    let total = deployments.len();
    let mut waves = Vec::with_capacity(percentages.len());
    let mut taken = 0usize;
    for (i, &pct) in percentages.iter().enumerate() {
        let is_last = i + 1 == percentages.len();
        // The last wave always exactly consumes whatever integer-division
        // rounding left over, so rounding can never drop a deployment out
        // of every wave. `.max(taken + 1)` guarantees every wave (not just
        // the last) gets at least one deployment, given the
        // waves-<=-deployments check above.
        let boundary = if is_last {
            total
        } else {
            (total * pct as usize) / 100
        };
        let boundary = boundary.max(taken + 1).min(total);
        let wave_deployments = deployments[taken..boundary].to_vec();
        taken = boundary;
        waves.push(RolloutWave {
            name: format!("wave-{}-{pct}pct", i + 1),
            deployments: wave_deployments,
            max_unhealthy: 0,
            state: WaveState::Pending,
        });
    }

    Ok(RolloutPlan {
        target,
        waves,
        cursor: 0,
        status: RolloutStatus::Planned,
    })
}

/// D-792 — waves from named groups (the console's rings: canary, early,
/// broad), in the order given. An empty group is skipped rather than turned
/// into an empty wave, which the state machine would otherwise have to
/// special-case; no deployments at all is an error, as in [`plan_waves`].
pub fn plan_waves_by_groups<T>(
    target: T,
    groups: Vec<(String, Vec<DeploymentId>)>,
) -> Result<RolloutPlan<T>, FleetError> {
    let mut seen = std::collections::HashSet::new();
    let mut waves = Vec::with_capacity(groups.len());
    for (name, deployments) in groups {
        if deployments.is_empty() {
            continue;
        }
        if let Some(dup) = deployments.iter().find(|id| !seen.insert(**id)) {
            return Err(FleetError::InvalidRolloutPlan(format!(
                "deployment {dup} appears in more than one wave"
            )));
        }
        waves.push(RolloutWave {
            name,
            deployments,
            max_unhealthy: 0,
            state: WaveState::Pending,
        });
    }
    if waves.is_empty() {
        return Err(FleetError::InvalidRolloutPlan(
            "no deployments to roll out to".into(),
        ));
    }
    Ok(RolloutPlan {
        target,
        waves,
        cursor: 0,
        status: RolloutStatus::Planned,
    })
}

impl<T> RolloutPlan<T> {
    pub fn current_wave(&self) -> Option<&RolloutWave> {
        self.waves.get(self.cursor)
    }

    /// Begin the current wave (`Pending` -> `InProgress`). The async driver
    /// calls this right before it starts polling the wave's deployments.
    pub fn start_current_wave(&mut self) -> Result<(), FleetError> {
        let was_planned = self.status == RolloutStatus::Planned;
        let idx = self.cursor;
        let wave = self
            .waves
            .get_mut(idx)
            .ok_or_else(|| FleetError::InvalidRolloutTransition {
                attempted: "start the current wave".into(),
                current: "no waves left".into(),
            })?;
        if wave.state != WaveState::Pending {
            return Err(FleetError::InvalidRolloutTransition {
                attempted: "start the current wave".into(),
                current: format!("wave {:?} is already {:?}", wave.name, wave.state),
            });
        }
        wave.state = WaveState::InProgress;
        if was_planned {
            self.status = RolloutStatus::InProgress;
        }
        Ok(())
    }

    /// Records a wave's health outcome and either promotes to the next
    /// wave, completes the rollout, or halts it — the one transition every
    /// other outcome funnels through. `unhealthy_count` is the number of
    /// the current wave's deployments the caller could not confirm as
    /// matching `target` (see `fleet-migrations::orchestrator`).
    pub fn report_wave_health(&mut self, unhealthy_count: usize) -> Result<(), FleetError> {
        let idx = self.cursor;
        let last = self.waves.len().saturating_sub(1);
        let wave = self
            .waves
            .get_mut(idx)
            .ok_or_else(|| FleetError::InvalidRolloutTransition {
                attempted: "report wave health".into(),
                current: "no waves left".into(),
            })?;
        if wave.state != WaveState::InProgress {
            return Err(FleetError::InvalidRolloutTransition {
                attempted: "report wave health".into(),
                current: format!("wave {:?} is {:?}, not in progress", wave.name, wave.state),
            });
        }

        if unhealthy_count > wave.max_unhealthy {
            wave.state = WaveState::Unhealthy;
            self.status = RolloutStatus::Halted;
            return Ok(());
        }

        wave.state = WaveState::Healthy;
        if idx == last {
            self.status = RolloutStatus::Completed;
        } else {
            self.cursor = idx + 1;
            self.status = RolloutStatus::InProgress;
        }
        Ok(())
    }

    pub fn halt(&mut self) {
        self.status = RolloutStatus::Halted;
    }

    /// Re-arms a `Halted` plan so the async driver can drive it again — the
    /// transition `fleetctl`'s own `rollout run` help text ("progress is
    /// resumable: a halted plan can be re-run after the operator
    /// investigates") always claimed existed but nothing implemented.
    /// Without it a halted plan was terminal in practice: `run_rollout`'s
    /// loop only runs while the status is `Planned`/`InProgress`, so
    /// re-running a halted plan returned instantly having done nothing, and
    /// even if it had entered the loop, `start_current_wave` rejects the
    /// halted wave because its state is `Unhealthy`, not `Pending`.
    ///
    /// Resets ONLY the wave that halted (`cursor`'s), back to `Pending` —
    /// already-`Healthy` earlier waves keep their state, so resuming never
    /// re-drives a wave that already converged. Deliberately not named
    /// `retry`: it re-arms the state machine, it does not itself re-trigger
    /// anything (see `fleet_migrations::trigger` for what does).
    pub fn resume(&mut self) -> Result<(), FleetError> {
        if self.status != RolloutStatus::Halted {
            return Err(FleetError::InvalidRolloutTransition {
                attempted: "resume".into(),
                current: format!("{:?}, not Halted", self.status),
            });
        }
        let idx = self.cursor;
        let wave = self
            .waves
            .get_mut(idx)
            .ok_or_else(|| FleetError::InvalidRolloutTransition {
                attempted: "resume".into(),
                current: "no waves left".into(),
            })?;
        wave.state = WaveState::Pending;
        self.status = RolloutStatus::InProgress;
        Ok(())
    }

    /// Marks the plan as rolled back. Does not itself perform a rollback —
    /// `P-fleet-control-plane.md` §4(c)/§7 designs rollback as "re-point
    /// deployments at the prior target and run a new `RolloutPlan`," not a
    /// distinct revert engine (the same "don't add a second way to do
    /// something the platform already does one way" reasoning D-214 records
    /// for `core_solution` rollback). This just records that outcome on the
    /// halted plan for audit/history purposes.
    pub fn mark_rolled_back(&mut self) -> Result<(), FleetError> {
        if self.status != RolloutStatus::Halted {
            return Err(FleetError::InvalidRolloutTransition {
                attempted: "mark rolled back".into(),
                current: format!("{:?}, not Halted", self.status),
            });
        }
        self.status = RolloutStatus::RolledBack;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ids::{ConfigHash, ImageDigest, SchemaVersion};
    use super::*;

    fn target() -> FleetKey {
        FleetKey {
            image_digest: ImageDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            schema_version: SchemaVersion(5),
            config_hash: ConfigHash::new("cfg-1"),
        }
    }

    fn ids(n: usize) -> Vec<DeploymentId> {
        (0..n).map(|_| DeploymentId::new()).collect()
    }

    #[test]
    fn plan_waves_rejects_empty_deployments() {
        assert!(plan_waves(target(), &[], &[100]).is_err());
    }

    #[test]
    fn plan_waves_rejects_last_percentage_not_100() {
        assert!(plan_waves(target(), &ids(3), &[10, 50]).is_err());
    }

    #[test]
    fn plan_waves_rejects_non_increasing_percentages() {
        assert!(plan_waves(target(), &ids(3), &[50, 50, 100]).is_err());
    }

    #[test]
    fn plan_waves_rejects_more_waves_than_deployments() {
        assert!(plan_waves(target(), &ids(2), &[10, 50, 100]).is_err());
    }

    #[test]
    fn plan_waves_covers_every_deployment_exactly_once() {
        let deployments = ids(10);
        let plan = plan_waves(target(), &deployments, &[10, 50, 100]).unwrap();
        let covered: Vec<DeploymentId> = plan
            .waves
            .iter()
            .flat_map(|w| w.deployments.clone())
            .collect();
        assert_eq!(covered, deployments);
        assert!(plan.waves.iter().all(|w| !w.deployments.is_empty()));
    }

    #[test]
    fn plan_waves_small_fleet_gives_every_wave_at_least_one() {
        let deployments = ids(3);
        let plan = plan_waves(target(), &deployments, &[10, 50, 100]).unwrap();
        assert_eq!(
            plan.waves
                .iter()
                .map(|w| w.deployments.len())
                .collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
    }

    #[test]
    fn full_rollout_promotes_through_every_wave_to_completed() {
        let deployments = ids(4);
        let mut plan = plan_waves(target(), &deployments, &[50, 100]).unwrap();
        assert_eq!(plan.status, RolloutStatus::Planned);

        plan.start_current_wave().unwrap();
        assert_eq!(plan.status, RolloutStatus::InProgress);
        plan.report_wave_health(0).unwrap();
        assert_eq!(plan.cursor, 1);
        assert_eq!(plan.status, RolloutStatus::InProgress);

        plan.start_current_wave().unwrap();
        plan.report_wave_health(0).unwrap();
        assert_eq!(plan.status, RolloutStatus::Completed);
    }

    #[test]
    fn unhealthy_wave_halts_and_blocks_further_promotion() {
        let deployments = ids(4);
        let mut plan = plan_waves(target(), &deployments, &[50, 100]).unwrap();
        plan.start_current_wave().unwrap();
        plan.report_wave_health(1).unwrap(); // max_unhealthy defaults to 0
        assert_eq!(plan.status, RolloutStatus::Halted);
        assert_eq!(plan.waves[0].state, WaveState::Unhealthy);
        // Cursor never advanced past the halted wave.
        assert_eq!(plan.cursor, 0);
    }

    #[test]
    fn report_health_without_starting_the_wave_is_rejected() {
        let deployments = ids(2);
        let mut plan = plan_waves(target(), &deployments, &[100]).unwrap();
        assert!(plan.report_wave_health(0).is_err());
    }

    #[test]
    fn resume_requires_halted_status() {
        let mut plan = plan_waves(target(), &ids(2), &[100]).unwrap();
        assert!(plan.resume().is_err());
        plan.start_current_wave().unwrap();
        assert!(plan.resume().is_err()); // InProgress is not resumable either
    }

    #[test]
    fn resume_rearms_the_halted_wave_without_touching_healthy_ones() {
        let deployments = ids(4);
        let mut plan = plan_waves(target(), &deployments, &[50, 100]).unwrap();

        // Wave 1 converges, wave 2 halts.
        plan.start_current_wave().unwrap();
        plan.report_wave_health(0).unwrap();
        plan.start_current_wave().unwrap();
        plan.report_wave_health(1).unwrap();
        assert_eq!(plan.status, RolloutStatus::Halted);
        assert_eq!(plan.waves[1].state, WaveState::Unhealthy);

        plan.resume().unwrap();
        assert_eq!(plan.status, RolloutStatus::InProgress);
        // Only the halted wave was re-armed; wave 1 stays converged so a
        // resume never re-drives a wave that already succeeded.
        assert_eq!(plan.waves[0].state, WaveState::Healthy);
        assert_eq!(plan.waves[1].state, WaveState::Pending);
        assert_eq!(plan.cursor, 1);

        // And the re-armed wave can now actually be driven to completion.
        plan.start_current_wave().unwrap();
        plan.report_wave_health(0).unwrap();
        assert_eq!(plan.status, RolloutStatus::Completed);
    }

    #[test]
    fn mark_rolled_back_requires_halted_status() {
        let deployments = ids(2);
        let mut plan = plan_waves(target(), &deployments, &[100]).unwrap();
        assert!(plan.mark_rolled_back().is_err());
        plan.start_current_wave().unwrap();
        plan.report_wave_health(1).unwrap();
        assert_eq!(plan.status, RolloutStatus::Halted);
        plan.mark_rolled_back().unwrap();
        assert_eq!(plan.status, RolloutStatus::RolledBack);
    }

    #[test]
    fn plan_waves_by_groups_skips_empty_groups_in_order() {
        let canary = ids(1);
        let broad = ids(2);
        let plan = plan_waves_by_groups(
            "release-1",
            vec![
                ("canary".to_string(), canary.clone()),
                ("early".to_string(), Vec::new()),
                ("broad".to_string(), broad.clone()),
            ],
        )
        .unwrap();
        assert_eq!(plan.waves.len(), 2);
        assert_eq!(plan.waves[0].name, "canary");
        assert_eq!(plan.waves[0].deployments, canary);
        assert_eq!(plan.waves[1].deployments, broad);
        assert_eq!(plan.status, RolloutStatus::Planned);
        assert_eq!(plan.target, "release-1");
    }

    #[test]
    fn plan_waves_by_groups_rejects_no_deployments_and_duplicates() {
        assert!(plan_waves_by_groups((), vec![("broad".to_string(), Vec::new())]).is_err());
        let one = ids(1);
        assert!(
            plan_waves_by_groups(
                (),
                vec![
                    ("canary".to_string(), one.clone()),
                    ("broad".to_string(), one),
                ],
            )
            .is_err()
        );
    }
}
