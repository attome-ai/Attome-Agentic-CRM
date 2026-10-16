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
