//! The schedule ledger: a periodic job runs **once per slot** across any
//! number of workers and restarts.
//!
//! Enqueue deduplication ([`crate::enqueue_dedup`] with a fixed key) blocks a
//! second row only while one is live, which closes *overlap* but does not
//! bound how often a slot runs: a worker that starts while no earlier row is
//! live enqueues again, so N workers could run one slot N times.
//!
//! The ledger is the gate in front of that: one row per schedule, claimed by a
//! single `UPDATE ... WHERE next_due_at <= now()` compare-and-swap. Exactly one
//! caller wins each slot and enqueues; every other caller sees a row that is
//! not due and does nothing. The dedup key stays behind it as the overlap
//! guard, so a slot whose job is still running cannot double-enqueue.
//!
//! No leader election, no advisory lock, no second broker: one table
//! (`job_schedule`, migration `0001_job_queue.sql`) and one short transaction
//! per tick per schedule.

use chrono::{DateTime, Utc};

/// One schedule's persisted state. Backs the ledger's own observability
/// (BJB-14b) and lets tests assert slot behaviour without re-deriving it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduleState {
    pub name: String,
    pub interval_secs: i32,
    pub next_due_at: DateTime<Utc>,
    pub last_enqueued_at: Option<DateTime<Utc>>,
    pub last_succeeded_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// Claims one schedule's current slot and enqueues `job` if this caller won
/// it.
///
/// `name` is the schedule's stable identity — deliberately the same string
/// as the scheduler's existing dedup key (D-618), so there is exactly one name
/// per periodic job and the two mechanisms cannot drift apart.
///
/// Returns `Ok(true)` when **this call won the slot** (the row was due and
/// this call advanced it). Another replica in the same slot, or a restart
/// inside it, gets `Ok(false)` and enqueues nothing. A `true` does not
/// promise a new `apalis.jobs` row: if the previous slot's job is still live,
/// [`crate::enqueue_in_tx_dedup`] is a no-op and the slot is simply skipped —
/// the same overlap guard D-165 established.
///
/// One short transaction: register-if-new, take the CAS, enqueue, commit. A
/// crash after the CAS but before the commit rolls the whole slot back, so the
/// next tick re-claims it rather than losing it.
#[expect(
    clippy::disallowed_methods,
    reason = "attome-jobs' whole public surface is `sqlx::Error`, so it cannot adopt \
              `attome_db::tx::begin`'s `AppError`; a tick that cannot get a connection fails \
              the tick, which the scheduler logs and re-claims on the next interval"
)]
pub async fn tick<J: crate::Job>(
    pool: &attome_db::DbPool,
    name: &str,
    interval: std::time::Duration,
    job: J,
) -> Result<bool, sqlx::Error> {
    let interval_secs = interval_secs(interval);

    let mut tx = pool.begin().await?;

    // Register on first sight, due immediately so a brand-new schedule's first
    // tick claims its slot at once. The interval is kept current on every tick
    // (a redeploy that changes a scheduler's interval should show up in the
    // ledger), but only written when it actually changed, so the common case
    // adds no writes.
    sqlx::query(attome_db::tagged_sql!(
        "jobs.schedule",
        "INSERT INTO job_schedule (name, interval_secs) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE \
             SET interval_secs = EXCLUDED.interval_secs, updated_at = now() \
             WHERE job_schedule.interval_secs <> EXCLUDED.interval_secs"
    ))
    .bind(name)
    .bind(interval_secs)
    .execute(&mut *tx)
    .await?;

    // The slot CAS. `now()` is the transaction's own start time, so a caller
    // that loses simply reads the winner's already-advanced `next_due_at`.
    let claimed: Option<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.schedule",
        "UPDATE job_schedule \
         SET next_due_at = now() + make_interval(secs => $2), \
             last_enqueued_at = now(), \
             row_version = row_version + 1, \
             updated_at = now() \
         WHERE name = $1 AND next_due_at <= now() \
         RETURNING name"
    ))
    .bind(name)
    .bind(interval_secs)
    .fetch_optional(&mut *tx)
    .await?;

    if claimed.is_none() {
        tx.commit().await?;
        return Ok(false);
    }

    crate::enqueue_in_tx_dedup(&mut tx, job, name).await?;
    tx.commit().await?;
    Ok(true)
}

/// Stamps a schedule's last successful run (BJB-4d), called by the worker
/// wrapper (`server::jobs::handle_platform_job`) after a schedule-originated
/// kind's handler returns `Ok`. Backs
/// `job_schedule_last_success_age_seconds{name}` (BJB-14b) — the signal that
/// distinguishes "the scheduler is ticking" from "the sweep is actually
/// running and succeeding".
pub async fn mark_succeeded(pool: &attome_db::DbPool, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query(attome_db::tagged_sql!(
        "jobs.schedule",
        "UPDATE job_schedule SET last_succeeded_at = now(), updated_at = now() \
         WHERE name = $1"
    ))
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every schedule's persisted row, ordered by name — the metrics refresh
/// loop's read (BJB-14b) and tests' inspection point.
pub async fn all(pool: &attome_db::DbPool) -> Result<Vec<ScheduleState>, sqlx::Error> {
    sqlx::query_as(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT name, interval_secs, next_due_at, last_enqueued_at, last_succeeded_at, \
                row_version \
         FROM job_schedule ORDER BY name"
    ))
    .fetch_all(pool)
    .await
}

/// Seconds since one schedule last succeeded, or `None` when it has never
/// succeeded. The gauge behind
/// `job_schedule_last_success_age_seconds{name}`: an alert threshold is
/// `2 ×` the schedule's own interval (plan §1).
pub async fn last_success_age_seconds(
    pool: &attome_db::DbPool,
    name: &str,
) -> Result<Option<f64>, sqlx::Error> {
    // Both "no row for this schedule" and "a row that has never succeeded"
    // are `None`: the caller (an alert on the age gauge) treats both as
    // "nothing has succeeded yet".
    let age: Option<Option<f64>> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT EXTRACT(EPOCH FROM (now() - last_succeeded_at))::float8 \
         FROM job_schedule WHERE name = $1"
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(age.flatten())
}

/// `(name, seconds since last success)` for every registered schedule — one
/// query for the metrics refresh loop, `None` for a schedule that has not
/// succeeded yet.
pub async fn last_success_ages(
    pool: &attome_db::DbPool,
) -> Result<Vec<(String, Option<f64>)>, sqlx::Error> {
    sqlx::query_as(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT name, EXTRACT(EPOCH FROM (now() - last_succeeded_at))::float8 \
         FROM job_schedule ORDER BY name"
    ))
    .fetch_all(pool)
    .await
}

/// A duration as whole seconds for `make_interval`/`interval_secs`, never
/// zero (the table's own CHECK) and never negative.
fn interval_secs(interval: std::time::Duration) -> i32 {
    interval.as_secs().clamp(1, i32::MAX as u64) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_secs_is_never_zero_or_negative() {
        assert_eq!(interval_secs(std::time::Duration::ZERO), 1);
        assert_eq!(interval_secs(std::time::Duration::from_millis(999)), 1);
        assert_eq!(interval_secs(std::time::Duration::from_secs(60)), 60);
        assert_eq!(
            interval_secs(std::time::Duration::from_secs(u64::MAX)),
            i32::MAX
        );
    }
}
