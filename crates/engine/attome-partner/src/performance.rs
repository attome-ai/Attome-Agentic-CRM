//! F9-T9: one `partner_performance_snapshot` per partner per day, written
//! nightly for the portal scorecard and sales reporting.
//!
//! A snapshot carries `partner_account_ref`, the field a partner's portal role
//! scopes reads by, so the scorecard reads snapshots: a stored query cannot
//! bind the caller's partner. The pack's stored queries are internal reports,
//! grouped by partner.
//!
//! Revenue, pipeline and win rate cover the 12 months to `as_of`, as tier
//! evaluation does. `win_rate` is won over closed, and empty with nothing
//! closed. `mdf_attributed_revenue` stays empty: nothing links a fund to the
//! deals it produced.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use uuid::Uuid;

use crate::support::installed;

/// The nightly job's name.
pub const ROLLUP_JOB: &str = "partner_performance_rollup";
/// Partners read per query.
const BATCH: i64 = 200;
const ENTITY: &str = "partner_performance_snapshot";

/// Won over closed, as a percentage; `None` with nothing closed. Pure.
pub fn win_rate(won: i64, closed: i64) -> Option<f64> {
    (closed > 0).then(|| won as f64 * 100.0 / closed as f64)
}

/// Writes `partner`'s snapshot for `as_of`, replacing the day's earlier one.
async fn write_snapshot(
    state: &EngineState,
    partner: Uuid,
    as_of: NaiveDate,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-partner/performance:{partner}:{as_of}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this partner's snapshot is being written",
        ));
    }
    let (pipeline, won_revenue, won, closed): (f64, f64, i64, i64) = sqlx::query_as(
        "SELECT \
           COALESCE(sum(amount) FILTER (WHERE stage NOT IN ('closed_won', 'closed_lost')), 0)::float8, \
           COALESCE(sum(amount) FILTER (WHERE stage = 'closed_won'), 0)::float8, \
           count(*) FILTER (WHERE stage = 'closed_won'), \
           count(*) FILTER (WHERE stage IN ('closed_won', 'closed_lost')) \
           FROM opportunity \
          WHERE partner_account_ref = $1 AND close_date > $2::date - interval '12 months' \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(partner)
    .bind(as_of)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (accept_hours, certified, mdf_spent): (Option<f64>, i64, f64) = sqlx::query_as(
        "SELECT \
           (SELECT avg(extract(epoch FROM partner_responded_at - partner_offered_at) / 3600)::float8 \
              FROM lead \
             WHERE partner_account_ref = $1 AND partner_status = 'accepted' \
               AND partner_responded_at > $2::date - interval '12 months'), \
           (SELECT count(DISTINCT partner_contact_ref) FROM partner_certification \
             WHERE partner_account_ref = $1 AND partner_contact_ref IS NOT NULL \
               AND (expires_on IS NULL OR expires_on > $2) \
               AND (is_active IS NULL OR is_active = true)), \
           (SELECT COALESCE(sum(c.amount), 0)::float8 FROM mdf_claim c \
              JOIN mdf_request r ON r.id = c.request_ref \
              JOIN mdf_fund f ON f.id = r.fund_ref \
             WHERE f.partner_account_ref = $1 AND c.status = 'approved' \
               AND (c.is_active IS NULL OR c.is_active = true))",
    )
    .bind(partner)
    .bind(as_of)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "DELETE FROM partner_performance_snapshot WHERE partner_account_ref = $1 AND as_of = $2",
    )
    .bind(partner)
    .bind(as_of)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO partner_performance_snapshot \
             (partner_account_ref, as_of, pipeline, won_revenue, win_rate, avg_accept_hours, \
              certified_people, mdf_spent) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(partner)
    .bind(as_of)
    .bind(pipeline)
    .bind(won_revenue)
    .bind(win_rate(won, closed))
    .bind(accept_hours)
    .bind(certified as f64)
    .bind(mdf_spent)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await
}

/// Writes every active partner's snapshot for `as_of`; how many were written.
/// Running it again the same day leaves one snapshot per partner.
pub async fn rollup(state: &EngineState, as_of: NaiveDate) -> Result<u64, AppError> {
    let db = &state.base.db;
    let mut after = Uuid::nil();
    let mut written = 0;
    loop {
        let partners: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM account \
              WHERE is_partner = true AND (is_active IS NULL OR is_active = true) AND id > $1 \
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = partners.last() else { break };
        after = *last;
        let done = (partners.len() as i64) < BATCH;
        for partner in partners {
            match write_snapshot(state, partner, as_of).await {
                Ok(()) => written += 1,
                // One partner's failure leaves the others written.
                Err(error) => tracing::warn!(%partner, %error, "partner snapshot not written"),
            }
        }
        if done {
            break;
        }
    }
    Ok(written)
}

/// The nightly job: today's snapshots, once the pack that holds them is in.
pub async fn rollup_tick(state: &EngineState) -> Result<u64, AppError> {
    if !installed(&state.base.db, ENTITY, "as_of").await? {
        return Ok(0);
    }
    rollup(state, Utc::now().date_naive()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win_rate_is_won_over_closed() {
        assert_eq!(win_rate(0, 0), None);
        assert_eq!(win_rate(0, 4), Some(0.0));
        assert_eq!(win_rate(1, 4), Some(25.0));
    }
}
