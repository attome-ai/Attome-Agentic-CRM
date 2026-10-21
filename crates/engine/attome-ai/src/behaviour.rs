//! AH5-T1: what each agent normally does, as the baseline its departures
//! are measured against (AH5-T2).
//!
//! - [`roll_up_hour`] fills `ai_agent_activity_hourly` for one hour: per
//!   agent (the session's `agent_definition_ref`), its completed calls
//!   counted by the action's limit class (AH4: record writes, deletes, and
//!   outside calls or messages sent) and the entities its agent-initiated
//!   audit headers name. Re-running an hour replaces its rows.
//! - [`recompute_baselines`] writes `ai_agent_baseline` from the last 28 days
//!   of hourly rows: the mean and spread of writes and deletes per hour,
//!   counting the agent's quiet hours as zero ([`mean_stddev`]), the entities
//!   it used, the hours of the day it works (on at least two different days,
//!   [`usual_hours`]) and when its activity began.
//!
//! The registered job [`ROLLUP_JOB`] runs hourly: it rolls up the hour just
//! ended and, in the 03:00 UTC hour, recomputes the baselines. Both steps are
//! idempotent, so a repeated or late run only rewrites the same rows.
//!
//! **Departures** (AH5-T2, [`check_departures`], job [`CHECK_JOB`] every five
//! minutes): each agent with at least [`LEARNING_DAYS`] of history has the
//! current hour so far compared with its baseline ([`departures`]): writes
//! or deletes above the mean plus [`SPREADS`] standard deviations (and at
//! least [`MIN_WRITES`] or [`MIN_DELETES`], so a quiet agent's small bump
//! is not one), an entity it has never written, and writes in an hour of the
//! day it does not work. A departure is logged for now; AH5-T3 stops the
//! agent on one.

use std::collections::{BTreeMap, BTreeSet};

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, DurationRound, Timelike, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::descriptor::LimitClass;

/// The registered job that rolls up activity and recomputes baselines.
pub const ROLLUP_JOB: &str = "ai_agent_behaviour_rollup";
/// How far back a baseline looks.
pub const BASELINE_DAYS: i64 = 28;
/// The UTC hour in which baselines are recomputed.
pub const BASELINE_HOUR: u32 = 3;
/// The registered job that checks for departures.
pub const CHECK_JOB: &str = "ai_agent_behaviour_check";
/// How many standard deviations above its mean an hour must be to depart.
pub const SPREADS: f64 = 4.0;
/// The fewest writes in an hour that can be a volume departure.
pub const MIN_WRITES: i32 = 20;
/// The fewest deletes in an hour that can be a delete departure.
pub const MIN_DELETES: i32 = 5;
/// The days of history an agent needs before it is checked.
pub const LEARNING_DAYS: i64 = 7;

/// What an agent did differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepartureKind {
    Volume,
    Deletes,
    NewEntity,
    OutsideHours,
}

/// One departure from an agent's baseline.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Departure {
    pub agent_ref: Uuid,
    pub kind: DepartureKind,
    pub observed: f64,
    pub expected: f64,
    /// The entity, for a new-entity departure.
    pub entity: Option<String>,
}

/// An agent's baseline as the check reads it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Baseline {
    pub first_activity_at: Option<DateTime<Utc>>,
    pub mean_writes: f64,
    pub stddev_writes: f64,
    pub mean_deletes: f64,
    pub stddev_deletes: f64,
    pub usual_entities: BTreeSet<String>,
    pub usual_hours: BTreeSet<i16>,
}

/// One agent's activity in one hour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HourActivity {
    pub writes: i32,
    pub deletes: i32,
    pub external_calls: i32,
    pub entities: BTreeSet<String>,
}

impl HourActivity {
    /// Counts `calls` completed calls of an action in `class`. Pure.
    pub fn count(&mut self, class: LimitClass, calls: i32) {
        match class {
            LimitClass::RecordChange => self.writes += calls,
            LimitClass::Delete => self.deletes += calls,
            LimitClass::ExternalCall | LimitClass::MessageSend => self.external_calls += calls,
            LimitClass::None => {}
        }
    }
}

/// Mean and population standard deviation of `values` over `n`
/// observations, the observations not listed being zero (an agent's quiet
/// hours). `None` when `n` is zero. Pure.
pub fn mean_stddev(values: &[f64], n: usize) -> Option<(f64, f64)> {
    if n == 0 {
        return None;
    }
    let count = n as f64;
    let mean = values.iter().sum::<f64>() / count;
    let squares = values.iter().map(|v| v * v).sum::<f64>() / count;
    let variance = (squares - mean * mean).max(0.0);
    Some((mean, variance.sqrt()))
}

/// The hours of the day (UTC) with writes on at least two different days,
/// or on any day while there is only one day of data. Pure.
pub fn usual_hours(active: &[DateTime<Utc>]) -> Vec<i16> {
    let mut days_per_hour: BTreeMap<u32, BTreeSet<chrono::NaiveDate>> = BTreeMap::new();
    for at in active {
        days_per_hour
            .entry(at.hour())
            .or_default()
            .insert(at.date_naive());
    }
    let days: BTreeSet<chrono::NaiveDate> = active.iter().map(DateTime::date_naive).collect();
    let needed = if days.len() < 2 { 1 } else { 2 };
    days_per_hour
        .into_iter()
        .filter(|(_, d)| d.len() >= needed)
        .filter_map(|(hour, _)| i16::try_from(hour).ok())
        .collect()
}

/// Each agent's activity between `start` and `end`.
async fn activity(
    db: &DbPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<BTreeMap<Uuid, HourActivity>, AppError> {
    let calls: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT s.agent_definition_ref, i.action_id, count(*) \
           FROM action_invocation i JOIN agent_session s ON s.id = i.agent_session_id \
          WHERE i.created_at >= $1 AND i.created_at < $2 AND i.outcome = 'completed' \
            AND s.agent_definition_ref IS NOT NULL \
          GROUP BY 1, 2",
    )
    .bind(start)
    .bind(end)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let entities: Vec<(Uuid, Vec<String>)> = sqlx::query_as(
        "SELECT s.agent_definition_ref, array_agg(DISTINCT h.entity_name::text) \
           FROM audit_header h JOIN agent_session s ON s.id = h.agent_session_id \
          WHERE h.initiator = 1 AND h.created_at >= $1 AND h.created_at < $2 \
            AND h.entity_name IS NOT NULL AND s.agent_definition_ref IS NOT NULL \
          GROUP BY 1",
    )
    .bind(start)
    .bind(end)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut per_agent: BTreeMap<Uuid, HourActivity> = BTreeMap::new();
    for (agent, action, n) in calls {
        let class = crate::engine::REGISTRY
            .resolve(&action)
            .map_or(LimitClass::None, |d| d.limit_class());
        let n = i32::try_from(n).unwrap_or(i32::MAX);
        per_agent.entry(agent).or_default().count(class, n);
    }
    for (agent, names) in entities {
        per_agent.entry(agent).or_default().entities.extend(names);
    }
    Ok(per_agent)
}

/// Fills `ai_agent_activity_hourly` for the hour starting at `hour`
/// (truncated to the hour). Returns how many agents had activity.
pub async fn roll_up_hour(db: &DbPool, hour: DateTime<Utc>) -> Result<usize, AppError> {
    let start = hour
        .duration_trunc(Duration::hours(1))
        .map_err(AppError::internal)?;
    let end = start + Duration::hours(1);
    let per_agent = activity(db, start, end).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM ai_agent_activity_hourly WHERE hour = $1")
        .bind(start)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for (agent, a) in &per_agent {
        let entities: Vec<&str> = a.entities.iter().map(String::as_str).collect();
        sqlx::query(
            "INSERT INTO ai_agent_activity_hourly \
                 (agent_ref, hour, writes, deletes, external_calls, entities) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(agent)
        .bind(start)
        .bind(a.writes)
        .bind(a.deletes)
        .bind(a.external_calls)
        .bind(&entities)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(per_agent.len())
}

type HourlyRow = (Uuid, DateTime<Utc>, i32, i32, Vec<String>);

/// Writes every agent's baseline from its last [`BASELINE_DAYS`] of hourly
/// rows, as at `now`. Returns how many agents it covered.
pub async fn recompute_baselines(db: &DbPool, now: DateTime<Utc>) -> Result<usize, AppError> {
    let since = now - Duration::days(BASELINE_DAYS);
    let rows: Vec<HourlyRow> = sqlx::query_as(
        "SELECT agent_ref, hour, writes, deletes, entities FROM ai_agent_activity_hourly \
          WHERE hour >= $1 ORDER BY agent_ref, hour",
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_agent: BTreeMap<Uuid, Vec<HourlyRow>> = BTreeMap::new();
    for row in rows {
        by_agent.entry(row.0).or_default().push(row);
    }
    let window_hours = usize::try_from(BASELINE_DAYS * 24).unwrap_or(672);
    let mut tx = attome_db::tx::begin(db).await?;
    for (agent, rows) in &by_agent {
        let first = rows.first().map(|r| r.1);
        // Quiet hours count from the first hour the agent was seen.
        let observed = first.map_or(1, |f| {
            usize::try_from((now - f).num_hours())
                .unwrap_or(1)
                .clamp(1, window_hours)
        });
        let writes: Vec<f64> = rows.iter().map(|r| f64::from(r.2)).collect();
        let deletes: Vec<f64> = rows.iter().map(|r| f64::from(r.3)).collect();
        let (mean_w, sd_w) = mean_stddev(&writes, observed).unwrap_or((0.0, 0.0));
        let (mean_d, sd_d) = mean_stddev(&deletes, observed).unwrap_or((0.0, 0.0));
        let entities: BTreeSet<&str> = rows
            .iter()
            .flat_map(|r| r.4.iter().map(String::as_str))
            .collect();
        let entities: Vec<&str> = entities.into_iter().collect();
        let active: Vec<DateTime<Utc>> = rows.iter().filter(|r| r.2 > 0).map(|r| r.1).collect();
        sqlx::query(
            "INSERT INTO ai_agent_baseline \
                 (agent_ref, computed_at, first_activity_at, mean_writes_per_hour, \
                  stddev_writes_per_hour, mean_deletes_per_hour, stddev_deletes_per_hour, \
                  usual_entities, usual_hours) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (agent_ref) DO UPDATE SET \
                 computed_at = EXCLUDED.computed_at, \
                 first_activity_at = EXCLUDED.first_activity_at, \
                 mean_writes_per_hour = EXCLUDED.mean_writes_per_hour, \
                 stddev_writes_per_hour = EXCLUDED.stddev_writes_per_hour, \
                 mean_deletes_per_hour = EXCLUDED.mean_deletes_per_hour, \
                 stddev_deletes_per_hour = EXCLUDED.stddev_deletes_per_hour, \
                 usual_entities = EXCLUDED.usual_entities, \
                 usual_hours = EXCLUDED.usual_hours",
        )
        .bind(agent)
        .bind(now)
        .bind(first)
        .bind(mean_w as f32)
        .bind(sd_w as f32)
        .bind(mean_d as f32)
        .bind(sd_d as f32)
        .bind(&entities)
        .bind(usual_hours(&active))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(by_agent.len())
}

/// The departures of one agent's hour so far from its baseline, at
/// `hour_of_day` (UTC). Pure.
pub fn departures(
    agent: Uuid,
    now: &HourActivity,
    base: &Baseline,
    hour_of_day: i16,
) -> Vec<Departure> {
    let mut out = Vec::new();
    let departure = |kind, observed: f64, expected: f64, entity: Option<String>| Departure {
        agent_ref: agent,
        kind,
        observed,
        expected,
        entity,
    };
    let writes_limit = base.mean_writes + SPREADS * base.stddev_writes;
    if now.writes >= MIN_WRITES && f64::from(now.writes) > writes_limit {
        out.push(departure(
            DepartureKind::Volume,
            f64::from(now.writes),
            base.mean_writes,
            None,
        ));
    }
    let deletes_limit = base.mean_deletes + SPREADS * base.stddev_deletes;
    if now.deletes >= MIN_DELETES && f64::from(now.deletes) > deletes_limit {
        out.push(departure(
            DepartureKind::Deletes,
            f64::from(now.deletes),
            base.mean_deletes,
            None,
        ));
    }
    for entity in now.entities.difference(&base.usual_entities) {
        let d = departure(DepartureKind::NewEntity, 1.0, 0.0, Some(entity.clone()));
        out.push(d);
    }
    if now.writes > 0 && !base.usual_hours.is_empty() && !base.usual_hours.contains(&hour_of_day) {
        out.push(departure(
            DepartureKind::OutsideHours,
            f64::from(now.writes),
            0.0,
            None,
        ));
    }
    out
}

type BaselineRow = (
    Uuid,
    Option<DateTime<Utc>>,
    Option<f32>,
    Option<f32>,
    Option<f32>,
    Option<f32>,
    Vec<String>,
    Vec<i16>,
);

/// Every agent's departures in the current hour so far, as at `now`.
/// Agents still learning (under [`LEARNING_DAYS`] of history) are skipped.
pub async fn check_departures(db: &DbPool, now: DateTime<Utc>) -> Result<Vec<Departure>, AppError> {
    let start = now
        .duration_trunc(Duration::hours(1))
        .map_err(AppError::internal)?;
    let current = activity(db, start, now).await?;
    if current.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = current.keys().copied().collect();
    let rows: Vec<BaselineRow> = sqlx::query_as(
        "SELECT agent_ref, first_activity_at, mean_writes_per_hour, stddev_writes_per_hour, \
                mean_deletes_per_hour, stddev_deletes_per_hour, usual_entities, usual_hours \
           FROM ai_agent_baseline WHERE agent_ref = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let hour_of_day = i16::try_from(now.hour()).unwrap_or(0);
    let learned_before = now - Duration::days(LEARNING_DAYS);
    let mut out = Vec::new();
    for (agent, first, mw, sw, md, sd, entities, hours) in rows {
        if first.is_none_or(|f| f > learned_before) {
            continue;
        }
        let Some(now_activity) = current.get(&agent) else {
            continue;
        };
        let base = Baseline {
            first_activity_at: first,
            mean_writes: f64::from(mw.unwrap_or(0.0)),
            stddev_writes: f64::from(sw.unwrap_or(0.0)),
            mean_deletes: f64::from(md.unwrap_or(0.0)),
            stddev_deletes: f64::from(sd.unwrap_or(0.0)),
            usual_entities: entities.into_iter().collect(),
            usual_hours: hours.into_iter().collect(),
        };
        out.extend(departures(agent, now_activity, &base, hour_of_day));
    }
    Ok(out)
}

/// The five-minute run (job [`CHECK_JOB`]): finds and reports departures.
pub async fn run_check(state: &EngineState, now: DateTime<Utc>) -> Result<usize, AppError> {
    let found = check_departures(&state.base.db, now).await?;
    for d in &found {
        tracing::warn!(
            agent = %d.agent_ref,
            kind = ?d.kind,
            observed = d.observed,
            expected = d.expected,
            entity = d.entity.as_deref().unwrap_or(""),
            "agent departed from its baseline"
        );
    }
    Ok(found.len())
}

/// The hourly run (job [`ROLLUP_JOB`]): the hour just ended, and the
/// baselines in the [`BASELINE_HOUR`] UTC hour.
pub async fn run(state: &EngineState, now: DateTime<Utc>) -> Result<(), AppError> {
    let db = &state.base.db;
    let agents = roll_up_hour(db, now - Duration::hours(1)).await?;
    tracing::debug!(agents, "agent activity rolled up");
    if now.hour() == BASELINE_HOUR {
        let baselines = recompute_baselines(db, now).await?;
        tracing::info!(baselines, "agent baselines recomputed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn behaviour_mean_and_spread_count_quiet_hours_as_zero() {
        // Two busy hours of four writes among four hours.
        let (mean, sd) = mean_stddev(&[4.0, 4.0], 4).unwrap();
        assert!((mean - 2.0).abs() < 1e-9);
        assert!((sd - 2.0).abs() < 1e-9);
        let (mean, sd) = mean_stddev(&[5.0, 5.0, 5.0], 3).unwrap();
        assert!((mean - 5.0).abs() < 1e-9 && sd.abs() < 1e-9);
        assert_eq!(mean_stddev(&[], 0), None);
    }

    #[test]
    fn behaviour_counts_calls_by_limit_class() {
        let mut a = HourActivity::default();
        a.count(LimitClass::RecordChange, 3);
        a.count(LimitClass::Delete, 1);
        a.count(LimitClass::MessageSend, 2);
        a.count(LimitClass::ExternalCall, 1);
        a.count(LimitClass::None, 9);
        assert_eq!((a.writes, a.deletes, a.external_calls), (3, 1, 3));
    }

    fn baseline(mean: f64, sd: f64) -> Baseline {
        Baseline {
            first_activity_at: Some(at(1, 0)),
            mean_writes: mean,
            stddev_writes: sd,
            usual_entities: BTreeSet::from(["deal".to_owned()]),
            usual_hours: BTreeSet::from([9, 10]),
            ..Baseline::default()
        }
    }

    fn hour(writes: i32, entities: &[&str]) -> HourActivity {
        HourActivity {
            writes,
            entities: entities.iter().map(|e| (*e).to_owned()).collect(),
            ..HourActivity::default()
        }
    }

    #[test]
    fn behaviour_a_burst_departs() {
        let agent = Uuid::now_v7();
        let found = departures(agent, &hour(200, &["deal"]), &baseline(5.0, 2.0), 9);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, DepartureKind::Volume);
        assert!((found[0].observed - 200.0).abs() < 1e-9);
    }

    #[test]
    fn behaviour_normal_variation_does_not_depart() {
        let agent = Uuid::now_v7();
        let found = departures(agent, &hour(8, &["deal"]), &baseline(5.0, 2.0), 10);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn behaviour_a_new_entity_departs() {
        let agent = Uuid::now_v7();
        let now = hour(3, &["deal", "invoice"]);
        let found = departures(agent, &now, &baseline(5.0, 2.0), 9);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, DepartureKind::NewEntity);
        assert_eq!(found[0].entity.as_deref(), Some("invoice"));
    }

    #[test]
    fn behaviour_writes_outside_usual_hours_depart() {
        let agent = Uuid::now_v7();
        let found = departures(agent, &hour(2, &["deal"]), &baseline(5.0, 2.0), 3);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, DepartureKind::OutsideHours);
    }

    #[test]
    fn behaviour_usual_hours_need_two_days() {
        let active = [at(1, 9), at(2, 9), at(2, 23)];
        assert_eq!(usual_hours(&active), vec![9]);
        let one_day = [at(1, 9), at(1, 14)];
        assert_eq!(usual_hours(&one_day), vec![9, 14], "one day: every hour");
        assert!(usual_hours(&[]).is_empty());
    }
}
