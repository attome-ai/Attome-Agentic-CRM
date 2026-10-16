//! Cross-framework control mapping (roadmap R10-T1): one control can
//! satisfy requirements of several regulations through the many-to-many
//! `grc_control_requirement` links, so testing it once counts everywhere.
//!
//! [`coverage`] answers, per regulation: how many requirements it has, how
//! many are mapped to at least one active control, how many to a control
//! whose latest test was effective, and which requirements are gaps (no
//! active control). [`shared_controls`] lists the controls that serve more
//! than one regulation. [`load_coverage`] reads the GRC tables and calls
//! both.

use std::collections::{BTreeMap, HashMap, HashSet};

use attome_db::DbPool;
use attome_types::AppError;
use serde::Serialize;
use uuid::Uuid;

/// A control's state as coverage needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlState {
    pub active: bool,
    /// The latest tested result was `effective`.
    pub effective: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrameworkCoverage {
    pub regulation: Uuid,
    pub requirements: usize,
    /// Mapped to at least one active control.
    pub mapped: usize,
    /// Mapped to at least one active control last tested effective.
    pub effective: usize,
    /// Requirements with no active control.
    pub gaps: Vec<Uuid>,
}

/// Coverage per regulation. `requirements` are `(requirement, regulation)`;
/// `links` are `(control, requirement)`.
pub fn coverage(
    requirements: &[(Uuid, Uuid)],
    links: &[(Uuid, Uuid)],
    controls: &HashMap<Uuid, ControlState>,
) -> Vec<FrameworkCoverage> {
    let mut by_requirement: HashMap<Uuid, Vec<ControlState>> = HashMap::new();
    for (control, requirement) in links {
        if let Some(state) = controls.get(control) {
            by_requirement.entry(*requirement).or_default().push(*state);
        }
    }
    let mut by_regulation: BTreeMap<Uuid, FrameworkCoverage> = BTreeMap::new();
    for (requirement, regulation) in requirements {
        let entry = by_regulation
            .entry(*regulation)
            .or_insert_with(|| FrameworkCoverage {
                regulation: *regulation,
                requirements: 0,
                mapped: 0,
                effective: 0,
                gaps: Vec::new(),
            });
        entry.requirements += 1;
        let states = by_requirement
            .get(requirement)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if states.iter().any(|s| s.active) {
            entry.mapped += 1;
            if states.iter().any(|s| s.active && s.effective) {
                entry.effective += 1;
            }
        } else {
            entry.gaps.push(*requirement);
        }
    }
    by_regulation.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SharedControl {
    pub control: Uuid,
    pub regulations: Vec<Uuid>,
}

/// Controls whose requirements span more than one regulation.
pub fn shared_controls(
    requirements: &[(Uuid, Uuid)],
    links: &[(Uuid, Uuid)],
) -> Vec<SharedControl> {
    let regulation_of: HashMap<Uuid, Uuid> = requirements.iter().copied().collect();
    let mut per_control: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for (control, requirement) in links {
        if let Some(regulation) = regulation_of.get(requirement) {
            let list = per_control.entry(*control).or_default();
            if !list.contains(regulation) {
                list.push(*regulation);
            }
        }
    }
    per_control
        .into_iter()
        .filter(|(_, regs)| regs.len() > 1)
        .map(|(control, mut regulations)| {
            regulations.sort();
            SharedControl {
                control,
                regulations,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageReport {
    pub frameworks: Vec<FrameworkCoverage>,
    pub shared_controls: Vec<SharedControl>,
}

/// Reads requirements of active regulations, live links and controls with
/// their latest tested result, and reports coverage.
pub async fn load_coverage(db: &DbPool) -> Result<CoverageReport, AppError> {
    let requirements: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT q.id, q.regulation_id FROM grc_requirement q \
         JOIN grc_regulation r ON r.id = q.regulation_id \
         WHERE (q.is_active IS NULL OR q.is_active = true) \
           AND (r.is_active IS NULL OR r.is_active = true) AND r.status = 'active'",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let links: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT control_id, requirement_id FROM grc_control_requirement \
         WHERE (is_active IS NULL OR is_active = true) \
           AND control_id IS NOT NULL AND requirement_id IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT c.id, c.status, (SELECT i.result FROM grc_assessment_item i \
             WHERE i.control_id = c.id AND (i.is_active IS NULL OR i.is_active = true) \
               AND i.result IN ('effective', 'ineffective') \
             ORDER BY i.modified_at DESC NULLS LAST, i.created_at DESC LIMIT 1) \
         FROM grc_control c WHERE (c.is_active IS NULL OR c.is_active = true)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let controls: HashMap<Uuid, ControlState> = rows
        .into_iter()
        .map(|(id, status, result)| {
            (
                id,
                ControlState {
                    active: status.as_deref() == Some("active"),
                    effective: result.as_deref() == Some("effective"),
                },
            )
        })
        .collect();
    let live: HashSet<Uuid> = controls.keys().copied().collect();
    let links: Vec<(Uuid, Uuid)> = links
        .into_iter()
        .filter(|(c, _)| live.contains(c))
        .collect();
    Ok(CoverageReport {
        frameworks: coverage(&requirements, &links, &controls),
        shared_controls: shared_controls(&requirements, &links),
    })
}

#[cfg(test)]
mod control_mapping {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn one_control_covers_requirements_in_two_frameworks() {
        // Regulation 1 (ISO) has requirements 10, 11; regulation 2 (NCA)
        // has 20. Control 100 (active, effective) serves 10 and 20; control
        // 101 (active, never tested) serves 11; control 102 is retired.
        let requirements = [(u(10), u(1)), (u(11), u(1)), (u(20), u(2)), (u(21), u(2))];
        let links = [
            (u(100), u(10)),
            (u(100), u(20)),
            (u(101), u(11)),
            (u(102), u(21)),
        ];
        let controls = HashMap::from([
            (
                u(100),
                ControlState {
                    active: true,
                    effective: true,
                },
            ),
            (
                u(101),
                ControlState {
                    active: true,
                    effective: false,
                },
            ),
            (
                u(102),
                ControlState {
                    active: false,
                    effective: true,
                },
            ),
        ]);
        let cov = coverage(&requirements, &links, &controls);
        assert_eq!(
            cov,
            vec![
                FrameworkCoverage {
                    regulation: u(1),
                    requirements: 2,
                    mapped: 2,
                    effective: 1,
                    gaps: vec![],
                },
                FrameworkCoverage {
                    regulation: u(2),
                    requirements: 2,
                    mapped: 1,
                    effective: 1,
                    gaps: vec![u(21)],
                },
            ]
        );
        assert_eq!(
            shared_controls(&requirements, &links),
            vec![SharedControl {
                control: u(100),
                regulations: vec![u(1), u(2)],
            }]
        );
    }
}
