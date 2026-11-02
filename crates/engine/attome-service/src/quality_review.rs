//! G1-T4: sampled quality reviews of closed cases.
//!
//! With the setting [`SAMPLE_SETTING`] above 0 (0, the default, is off),
//! the weekly [`JOB`] picks for each agent up to that many of the cases they
//! resolved or closed in the week before (`service_ticket.assignee_id`, by
//! `resolved_at`, else its last change), and opens one
//! `service_quality_review` per case (platform changeset 0090) for the
//! agent's manager (the holders of the parent position of the agent's
//! position): `to_review`, to be scored on tone, accuracy and process. The
//! pick is fixed per week ([`sample`]), so a rerun picks the same cases, and
//! a case is never reviewed twice.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{Datelike, Duration, NaiveDate};
use uuid::Uuid;

/// The job's name.
pub const JOB: &str = "service_quality_sample";
/// Cases sampled per agent and week (0 is off).
pub const SAMPLE_SETTING: &str = "service.quality_review.sample_size";
/// The most a sample takes per agent.
const MAX_SAMPLE: usize = 50;

/// Up to `n` of `cases`, the same ones for the same `week`. Pure.
pub fn sample(cases: &[Uuid], n: usize, week: NaiveDate) -> Vec<Uuid> {
    let seed =
        u128::from(week.num_days_from_ce().unsigned_abs()).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut keyed: Vec<(u128, Uuid)> = cases.iter().map(|c| (c.as_u128() ^ seed, *c)).collect();
    keyed.sort_unstable();
    keyed.dedup_by_key(|(_, c)| *c);
    keyed.into_iter().take(n).map(|(_, c)| c).collect()
}

fn sample_size(state: &EngineState) -> usize {
    attome_core::setting_registry()
        .get(SAMPLE_SETTING)
        .and_then(|d| state.settings.load().resolve(d, None, None).0.as_u64())
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0)
        .min(MAX_SAMPLE)
}

/// Opens the reviews for the week starting `week` (the cases closed in the
/// seven days before it); how many were opened.
pub async fn sample_week(state: &EngineState, week: NaiveDate) -> Result<usize, AppError> {
    let n = sample_size(state);
    if n == 0 {
        return Ok(0);
    }
    let db = &state.base.db;
    let from = week - Duration::days(7);
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT t.assignee_id, t.id FROM service_ticket t \
          WHERE t.status::text IN ('resolved', 'closed') AND t.assignee_id IS NOT NULL \
            AND COALESCE(t.resolved_at, t.modified_at)::date >= $1 \
            AND COALESCE(t.resolved_at, t.modified_at)::date < $2 \
            AND (t.is_active IS NULL OR t.is_active = true) \
            AND NOT EXISTS (SELECT 1 FROM service_quality_review r \
                             WHERE r.ticket_ref = t.id \
                               AND (r.is_active IS NULL OR r.is_active = true)) \
          ORDER BY t.assignee_id, t.id",
    )
    .bind(from)
    .bind(week)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_agent: std::collections::BTreeMap<Uuid, Vec<Uuid>> = Default::default();
    for (agent, case) in rows {
        by_agent.entry(agent).or_default().push(case);
    }
    let mut opened = 0;
    for (agent, cases) in by_agent {
        let reviewer: Option<Uuid> = sqlx::query_scalar(
            "SELECT mgr.user_ref FROM user_account_mm_position own \
             JOIN position pos ON pos.id = own.position_ref AND pos.is_deleted = false \
             JOIN user_account_mm_position mgr \
                 ON mgr.position_ref = pos.parent_position_ref AND mgr.is_deleted = false \
             JOIN user_account u ON u.id = mgr.user_ref \
             WHERE own.user_ref = $1 AND own.is_deleted = false \
               AND (u.is_active IS NULL OR u.is_active = true) \
             ORDER BY mgr.user_ref LIMIT 1",
        )
        .bind(agent)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        for case in sample(&cases, n, week) {
            let made = sqlx::query(
                "INSERT INTO service_quality_review \
                     (id, ticket_ref, agent_ref, reviewer_ref, week, status, owner_ref, is_active, \
                      row_version, created_at) \
                 SELECT uuidv7(), $1, $2, $3, $4::timestamptz, 'to_review', $3, true, 0, now() \
                  WHERE NOT EXISTS (SELECT 1 FROM service_quality_review \
                                     WHERE ticket_ref = $1 \
                                       AND (is_active IS NULL OR is_active = true))",
            )
            .bind(case)
            .bind(agent)
            .bind(reviewer)
            .bind(week)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            opened += usize::try_from(made.rows_affected()).unwrap_or(0);
        }
    }
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn quality_review_sample_is_fixed_per_week() {
        let cases: Vec<Uuid> = (0..20).map(|_| Uuid::now_v7()).collect();
        let week = d(2026, 11, 2);
        let first = sample(&cases, 5, week);
        assert_eq!(first.len(), 5);
        assert_eq!(
            first,
            sample(&cases, 5, week),
            "the same week picks the same cases"
        );
        assert!(first.iter().all(|c| cases.contains(c)));
    }

    #[test]
    fn quality_review_sample_takes_at_most_what_there_is() {
        let cases: Vec<Uuid> = (0..3).map(|_| Uuid::now_v7()).collect();
        assert_eq!(sample(&cases, 5, d(2026, 11, 2)).len(), 3);
        assert!(sample(&cases, 0, d(2026, 11, 2)).is_empty());
        let twice = [cases[0], cases[0]];
        assert_eq!(sample(&twice, 5, d(2026, 11, 2)).len(), 1, "a case once");
    }
}
