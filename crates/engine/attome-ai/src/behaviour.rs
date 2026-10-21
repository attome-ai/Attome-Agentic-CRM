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

use std::collections::{BTreeMap, BTreeSet};

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, DurationRound, Timelike, Utc};
use uuid::Uuid;

use crate::descriptor::LimitClass;

/// The registered job that rolls up activity and recomputes baselines.
pub const ROLLUP_JOB: &str = "ai_agent_behaviour_rollup";
/// How far back a baseline looks.
pub const BASELINE_DAYS: i64 = 28;
/// The UTC hour in which baselines are recomputed.
pub const BASELINE_HOUR: u32 = 3;

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

/// Fills `ai_agent_activity_hourly` for the hour starting at `hour`
/// (truncated to the hour). Returns how many agents had activity.
pub async fn roll_up_hour(db: &DbPool, hour: DateTime<Utc>) -> Result<usize, AppError> {
    let start = hour
        .duration_trunc(Duration::hours(1))
        .map_err(AppError::internal)?;
    let end = start + Duration::hours(1);
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

    #[test]
    fn behaviour_usual_hours_need_two_days() {
        let active = [at(1, 9), at(2, 9), at(2, 23)];
        assert_eq!(usual_hours(&active), vec![9]);
        let one_day = [at(1, 9), at(1, 14)];
        assert_eq!(usual_hours(&one_day), vec![9, 14], "one day: every hour");
        assert!(usual_hours(&[]).is_empty());
    }
}
