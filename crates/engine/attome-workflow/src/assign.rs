//! The assign node (roadmap M11-T1): picks the owner of a record from a
//! candidate set — the members of a team, a queue or a role — by one of
//! five strategies:
//!
//! - `rule`: the first rule whose record attribute equals its value names
//!   the user;
//! - `round_robin`: the candidate after the one this node picked last
//!   (`workflow_assign_cursor`, per graph version and node, under a
//!   two-argument advisory lock);
//! - `least_loaded`: the candidate owning the fewest live records of the
//!   entity;
//! - `skills`: the candidate holding every required skill
//!   (`resource_skill`), highest total level first;
//! - `territory`: the owner of the territory the record names.
//!
//! Only active users are candidates. When the strategy finds nobody, the
//! fallback queue's members are tried round robin. The leave and working
//! hours filter joins when the leave engine (W6) exists.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Rule,
    RoundRobin,
    LeastLoaded,
    Skills,
    Territory,
}

impl Strategy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rule" => Some(Self::Rule),
            "round_robin" => Some(Self::RoundRobin),
            "least_loaded" => Some(Self::LeastLoaded),
            "skills" => Some(Self::Skills),
            "territory" => Some(Self::Territory),
            _ => None,
        }
    }
}

/// The candidate after `last` in `candidates` (the first when `last` is
/// not among them).
pub fn next_round_robin(candidates: &[Uuid], last: Option<Uuid>) -> Option<Uuid> {
    let position = last.and_then(|l| candidates.iter().position(|c| *c == l));
    match position {
        Some(i) => candidates.get((i + 1) % candidates.len()).copied(),
        None => candidates.first().copied(),
    }
}

/// The candidate with the fewest records; ties go to the earlier one.
pub fn least_loaded(candidates: &[Uuid], loads: &HashMap<Uuid, i64>) -> Option<Uuid> {
    candidates
        .iter()
        .enumerate()
        .min_by_key(|(i, c)| (loads.get(c).copied().unwrap_or(0), *i))
        .map(|(_, c)| *c)
}

/// The candidate holding every required skill (case-insensitive), highest
/// total level first; ties go to the earlier one.
pub fn best_skilled(
    candidates: &[Uuid],
    skills_of: &HashMap<Uuid, Vec<(String, f64)>>,
    required: &[String],
) -> Option<Uuid> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let held = skills_of.get(c)?;
            let mut total = 0.0;
            for need in required {
                let (_, level) = held.iter().find(|(s, _)| s.eq_ignore_ascii_case(need))?;
                total += level;
            }
            Some((total, i, *c))
        })
        .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)))
        .map(|(_, _, c)| c)
}

/// The user the first matching rule names. A rule is
/// `{"field": "...", "equals": <value>, "user": "<uuid>"}`.
pub fn by_rule(rules: &[Value], record: &serde_json::Map<String, Value>) -> Option<Uuid> {
    rules.iter().find_map(|rule| {
        let field = rule.get("field")?.as_str()?;
        let equals = rule.get("equals")?;
        let actual = record.get(field)?;
        let same = actual == equals
            || matches!((actual.as_str(), equals.as_str()), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b));
        if !same {
            return None;
        }
        Uuid::parse_str(rule.get("user")?.as_str()?).ok()
    })
}

/// Active members of a team, queue or role, in a stable order.
pub async fn candidates(
    state: &EngineState,
    team: Option<Uuid>,
    queue: Option<Uuid>,
    role: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    let db = &state.base.db;
    let mut users: Vec<Uuid> = Vec::new();
    if let Some(team) = team {
        users.extend(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
            )
            .bind(team)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?,
        );
    }
    if let Some(queue) = queue {
        users.extend(queue_members(state, queue).await?);
    }
    if let Some(role) = role {
        users.extend(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT user_ref FROM user_account_mm_role WHERE role_ref = $1 AND is_deleted = false",
            )
            .bind(role)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?,
        );
    }
    users.sort();
    users.dedup();
    let active: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_account WHERE id = ANY($1) AND is_active = true ORDER BY id",
    )
    .bind(&users)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(active)
}

/// Active members of a service work queue.
pub async fn queue_members(state: &EngineState, queue: Uuid) -> Result<Vec<Uuid>, AppError> {
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('service_work_queue_member') IS NOT NULL")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !installed {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(
        "SELECT user_ref FROM service_work_queue_member \
         WHERE queue_ref = $1 AND COALESCE(is_active, true) = true AND user_ref IS NOT NULL \
         ORDER BY user_ref",
    )
    .bind(queue)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Picks the next candidate round robin and stores it, under the node's
/// advisory lock; `Conflict` when another run holds it (the job retries).
pub async fn round_robin(
    state: &EngineState,
    version: Uuid,
    node_id: &str,
    candidates: &[Uuid],
) -> Result<Option<Uuid>, AppError> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-workflow/assign-rr:{version}:{node_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("another run is assigning on this node"));
    }
    let last: Option<Uuid> = sqlx::query_scalar(
        "SELECT last_user_id FROM workflow_assign_cursor \
         WHERE definition_version_id = $1 AND node_id = $2",
    )
    .bind(version)
    .bind(node_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(next) = next_round_robin(candidates, last) else {
        return Ok(None);
    };
    sqlx::query(
        "INSERT INTO workflow_assign_cursor (definition_version_id, node_id, last_user_id) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (definition_version_id, node_id) \
         DO UPDATE SET last_user_id = EXCLUDED.last_user_id, updated_at = now()",
    )
    .bind(version)
    .bind(node_id)
    .bind(next)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(next))
}

/// Live records of `entity` each candidate owns.
pub async fn loads(
    state: &EngineState,
    entity: &str,
    candidates: &[Uuid],
) -> Result<HashMap<Uuid, i64>, AppError> {
    let table = attome_core::quote_ident(entity);
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(&format!(
        "SELECT owner_ref, COUNT(*) FROM {table} \
         WHERE owner_ref = ANY($1) AND (is_active IS NULL OR is_active = true) GROUP BY owner_ref"
    ))
    .bind(candidates)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// The skills each candidate holds.
pub async fn skills(
    state: &EngineState,
    candidates: &[Uuid],
) -> Result<HashMap<Uuid, Vec<(String, f64)>>, AppError> {
    let rows: Vec<(Uuid, String, Option<f64>)> = sqlx::query_as(
        "SELECT user_id, skill, skill_level::float8 FROM resource_skill \
         WHERE user_id = ANY($1) AND (is_active IS NULL OR is_active = true) AND skill IS NOT NULL",
    )
    .bind(candidates)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out: HashMap<Uuid, Vec<(String, f64)>> = HashMap::new();
    for (user, skill, level) in rows {
        out.entry(user)
            .or_default()
            .push((skill, level.unwrap_or(1.0)));
    }
    Ok(out)
}

/// The owner of a territory.
pub async fn territory_owner(
    state: &EngineState,
    territory: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('territory') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(None);
    }
    Ok(sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT owner_ref FROM territory WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(territory)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten())
}

/// M11-T2: one past record to replay, with the owner it was given.
#[derive(Debug, Clone, PartialEq)]
pub struct PastAssignment {
    pub record_id: Uuid,
    pub record: serde_json::Map<String, Value>,
    /// The owner the record actually got; `None` when it has none.
    pub actual_owner: Option<Uuid>,
}

/// M11-T2: what a strategy needs that the records do not carry.
#[derive(Debug, Clone, Default)]
pub struct SimulationInputs {
    pub candidates: Vec<Uuid>,
    /// Live records each candidate owned when the replay starts.
    pub loads: HashMap<Uuid, i64>,
    pub skills_of: HashMap<Uuid, Vec<(String, f64)>>,
    pub required_skills: Vec<String>,
    pub rules: Vec<Value>,
    /// The territory owner each record resolves to, by record id.
    pub territory_owners: HashMap<Uuid, Uuid>,
}

/// M11-T2: how a strategy would have spread the replayed records.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct SimulationReport {
    pub records: usize,
    /// Records the strategy would give each user.
    pub simulated: HashMap<Uuid, usize>,
    /// Records each user actually got.
    pub actual: HashMap<Uuid, usize>,
    /// Records the strategy finds nobody for (the fallback queue would take
    /// them).
    pub unassigned: usize,
    /// Records the strategy gives someone other than their actual owner.
    pub changed: usize,
    /// The largest count over the smallest among candidates (1.0 is even;
    /// `None` when a candidate would get nothing).
    pub spread: Option<f64>,
}

/// M11-T2: replays `past` (oldest first) with `strategy`, as the assign node
/// would have run it record by record: round robin moves on after each pick,
/// least loaded counts each pick as one more record. Pure: the caller loads
/// the records and the inputs.
pub fn simulate_assignments(
    strategy: Strategy,
    past: &[PastAssignment],
    inputs: &SimulationInputs,
) -> SimulationReport {
    let mut report = SimulationReport {
        records: past.len(),
        ..SimulationReport::default()
    };
    let mut loads = inputs.loads.clone();
    let mut last: Option<Uuid> = None;
    for item in past {
        if let Some(owner) = item.actual_owner {
            *report.actual.entry(owner).or_default() += 1;
        }
        let pick = match strategy {
            Strategy::Rule => by_rule(&inputs.rules, &item.record),
            Strategy::RoundRobin => next_round_robin(&inputs.candidates, last),
            Strategy::LeastLoaded => least_loaded(&inputs.candidates, &loads),
            Strategy::Skills => best_skilled(
                &inputs.candidates,
                &inputs.skills_of,
                &inputs.required_skills,
            ),
            Strategy::Territory => inputs.territory_owners.get(&item.record_id).copied(),
        };
        match pick {
            Some(user) => {
                last = Some(user);
                *loads.entry(user).or_default() += 1;
                *report.simulated.entry(user).or_default() += 1;
                if item.actual_owner != Some(user) {
                    report.changed += 1;
                }
            }
            None => report.unassigned += 1,
        }
    }
    let counts: Vec<usize> = inputs
        .candidates
        .iter()
        .map(|c| report.simulated.get(c).copied().unwrap_or(0))
        .collect();
    report.spread = match (counts.iter().max(), counts.iter().min()) {
        (Some(&max), Some(&min)) if min > 0 => Some(max as f64 / min as f64),
        _ => None,
    };
    report
}

#[cfg(test)]
mod assign_simulation {
    use super::*;
    use serde_json::json;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn past(owners: &[u128], region: &str) -> Vec<PastAssignment> {
        owners
            .iter()
            .enumerate()
            .map(|(i, owner)| PastAssignment {
                record_id: u(100 + i as u128),
                record: json!({ "region": region })
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
                actual_owner: Some(u(*owner)),
            })
            .collect()
    }

    #[test]
    fn assign_simulation_round_robin_spreads_evenly() {
        let inputs = SimulationInputs {
            candidates: vec![u(1), u(2), u(3)],
            ..SimulationInputs::default()
        };
        let report = simulate_assignments(Strategy::RoundRobin, &past(&[1; 6], "east"), &inputs);
        assert_eq!(report.records, 6);
        assert_eq!(report.simulated.get(&u(2)), Some(&2));
        assert_eq!(report.spread, Some(1.0));
        assert_eq!(report.actual.get(&u(1)), Some(&6));
        assert_eq!(report.changed, 4, "two of six stay with their owner");
    }

    #[test]
    fn assign_simulation_least_loaded_fills_the_emptiest_first() {
        let inputs = SimulationInputs {
            candidates: vec![u(1), u(2)],
            loads: HashMap::from([(u(1), 3)]),
            ..SimulationInputs::default()
        };
        let report = simulate_assignments(Strategy::LeastLoaded, &past(&[1; 5], "east"), &inputs);
        assert_eq!(
            report.simulated.get(&u(2)),
            Some(&4),
            "3 to catch up, then alternate"
        );
        assert_eq!(report.simulated.get(&u(1)), Some(&1));
        assert_eq!(report.spread, Some(4.0));
    }

    #[test]
    fn assign_simulation_counts_records_nobody_takes() {
        let inputs = SimulationInputs {
            candidates: vec![u(1)],
            rules: vec![json!({"field": "region", "equals": "west", "user": u(7).to_string()})],
            ..SimulationInputs::default()
        };
        let report = simulate_assignments(Strategy::Rule, &past(&[1, 1], "east"), &inputs);
        assert_eq!(report.unassigned, 2);
        assert_eq!(report.spread, None, "a candidate who gets nothing");
        let territory = simulate_assignments(
            Strategy::Territory,
            &past(&[1, 1], "east"),
            &SimulationInputs {
                territory_owners: HashMap::from([(u(100), u(1))]),
                ..inputs.clone()
            },
        );
        assert_eq!(territory.unassigned, 1);
        assert_eq!(territory.changed, 0);
    }
}

#[cfg(test)]
mod assign_node {
    use super::*;
    use serde_json::json;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn round_robin_cycles_and_starts_over_for_strangers() {
        let c = [u(1), u(2), u(3)];
        assert_eq!(next_round_robin(&c, None), Some(u(1)));
        assert_eq!(next_round_robin(&c, Some(u(1))), Some(u(2)));
        assert_eq!(next_round_robin(&c, Some(u(3))), Some(u(1)));
        assert_eq!(
            next_round_robin(&c, Some(u(9))),
            Some(u(1)),
            "a removed member"
        );
        assert_eq!(next_round_robin(&[], None), None);
    }

    #[test]
    fn least_loaded_prefers_the_emptiest_then_the_first() {
        let c = [u(1), u(2), u(3)];
        let loads = HashMap::from([(u(1), 5), (u(2), 2), (u(3), 2)]);
        assert_eq!(least_loaded(&c, &loads), Some(u(2)));
        assert_eq!(least_loaded(&c, &HashMap::new()), Some(u(1)));
    }

    #[test]
    fn skills_need_every_required_skill() {
        let c = [u(1), u(2), u(3)];
        let held = HashMap::from([
            (u(1), vec![("Arabic".to_owned(), 3.0)]),
            (
                u(2),
                vec![("arabic".to_owned(), 2.0), ("Billing".to_owned(), 2.0)],
            ),
            (
                u(3),
                vec![("Arabic".to_owned(), 5.0), ("billing".to_owned(), 1.0)],
            ),
        ]);
        let need = vec!["arabic".to_owned(), "billing".to_owned()];
        assert_eq!(best_skilled(&c, &held, &need), Some(u(3)), "6 beats 4");
        assert_eq!(best_skilled(&c, &held, &["French".to_owned()]), None);
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let rules = vec![
            json!({"field": "region", "equals": "east", "user": u(10).to_string()}),
            json!({"field": "region", "equals": "EAST", "user": u(11).to_string()}),
            json!({"field": "tier", "equals": 1, "user": u(12).to_string()}),
        ];
        let east = json!({"region": "East", "tier": 2});
        let gold = json!({"region": "west", "tier": 1});
        assert_eq!(
            by_rule(&rules, east.as_object().unwrap_or(&serde_json::Map::new())),
            Some(u(10))
        );
        assert_eq!(
            by_rule(&rules, gold.as_object().unwrap_or(&serde_json::Map::new())),
            Some(u(12))
        );
        assert_eq!(by_rule(&rules, &serde_json::Map::new()), None);
        assert_eq!(Strategy::parse("territory"), Some(Strategy::Territory));
    }
}
