//! D22-T9: nightly trend aggregates over the analysed calls.
//!
//! [`aggregate_day`] rebuilds one day's rows of `call_daily_aggregate` in
//! one transaction (the day's rows deleted, then written again), so running
//! it twice for a day gives the same rows. A call belongs to the day its
//! analysis finished (`call_analysis.analysed_at`) and to its activity
//! owner's first team (none when the owner has no team). Per team:
//!
//! - `calls`: analysed calls;
//! - `staff_talk_share`: the average share of talk time staff took;
//! - `question_rate`: the average questions per call, both sides;
//! - `scorecard_yes_rate`: the share of scorecard answers that are `yes`
//!   (the confirmed answer, else the proposed one) among `yes` and `no`;
//! - `tracker_hits`, per team and tracker: the tracker's hits.
//!
//! The nightly job ([`JOB`]) aggregates yesterday. Trends are read from
//! these rows by the call intelligence stored queries (platform changeset
//! 0089), never computed over raw findings at read time.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;

/// The nightly job's name.
pub const JOB: &str = "callintel_nightly_aggregate";

/// Rebuilds `day`'s aggregate rows; how many were written.
pub async fn aggregate_day(state: &EngineState, day: NaiveDate) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM call_daily_aggregate WHERE day::date = $1")
        .bind(day)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let written = sqlx::query(
        "WITH calls AS ( \
             SELECT a.id, a.staff_talk_share::float8 AS share, \
                    (COALESCE(a.staff_questions, 0) + COALESCE(a.customer_questions, 0))::float8 \
                        AS questions, \
                    (SELECT tm.team_ref::text FROM user_account_mm_team tm \
                      WHERE tm.user_ref = COALESCE(act.owner_ref, act.created_by) \
                        AND NOT tm.is_deleted \
                      ORDER BY tm.created_at, tm.team_ref LIMIT 1) AS team \
               FROM call_analysis a \
               LEFT JOIN activity act ON act.id::text = a.activity_id \
              WHERE a.status = 'done' AND a.analysed_at::date = $1 \
                AND (a.is_active IS NULL OR a.is_active = true)), \
         answers AS ( \
             SELECT c.team, COALESCE(s.confirmed_value, s.proposed_value) AS value \
               FROM calls c JOIN call_scorecard_answer s ON s.analysis_ref = c.id \
              WHERE (s.is_active IS NULL OR s.is_active = true)), \
         rows AS ( \
             SELECT team, NULL::text AS tracker, 'calls' AS metric, count(*)::float8 AS value \
               FROM calls GROUP BY team \
             UNION ALL \
             SELECT team, NULL, 'staff_talk_share', avg(share) FROM calls \
              WHERE share IS NOT NULL GROUP BY team \
             UNION ALL \
             SELECT team, NULL, 'question_rate', avg(questions) FROM calls GROUP BY team \
             UNION ALL \
             SELECT team, NULL, 'scorecard_yes_rate', \
                    (count(*) FILTER (WHERE value = 'yes'))::float8 / count(*)::float8 \
               FROM answers WHERE value IN ('yes', 'no') GROUP BY team \
             UNION ALL \
             SELECT c.team, f.tracker_ref::text, 'tracker_hits', count(*)::float8 \
               FROM calls c JOIN call_finding f ON f.analysis_ref = c.id \
              WHERE f.kind = 'tracker_hit' AND f.tracker_ref IS NOT NULL \
                AND (f.is_active IS NULL OR f.is_active = true) \
              GROUP BY c.team, f.tracker_ref) \
         INSERT INTO call_daily_aggregate \
             (id, day, team_ref, tracker_ref, metric, value, is_active, row_version, created_at) \
         SELECT uuidv7(), $1::timestamptz, team, tracker, metric, value, true, 0, now() FROM rows",
    )
    .bind(day)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_db::tx::commit(tx).await?;
    Ok(written)
}
