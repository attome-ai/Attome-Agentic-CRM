//! Y7-T3: the outbox's daily partitions. Migration 0320 partitions
//! `entity_change_event` by day on `created_at`; the change-feed prune job
//! keeps that up from then on:
//!
//! - [`ensure_ahead`] creates today's partition and the [`DAYS_AHEAD`] after
//!   it. A day whose rows already sit in the default partition (the job did
//!   not run for a while) has them moved into its new partition.
//! - [`drop_expired`] drops each day that ended `retention_days` ago or more
//!   and that holds nothing a consumer still needs: the floor [`super::prune`]
//!   keeps row by row, kept here for the whole day.
//! - [`prune_applied`] deletes consumers' applied rows whose event is gone.
//!   The foreign key that once cascaded them could not survive partitioning.
//!
//! The first two are DDL and run on the migrator pool (the table's owner);
//! `today` is the caller's clock, so a test can move it.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Duration, NaiveDate};

/// The partitioned outbox.
pub const TABLE: &str = "entity_change_event";

/// Days after today whose partitions exist ahead of time.
pub const DAYS_AHEAD: i64 = 3;

/// Applied rows [`prune_applied`] deletes per statement.
const APPLIED_BATCH: i64 = 5000;

/// The partition holding `day`'s events: `entity_change_event_dYYYYMMDD`.
pub fn partition_name(day: NaiveDate) -> String {
    format!("{TABLE}_d{}", day.format("%Y%m%d"))
}

/// The days [`ensure_ahead`] makes sure have a partition. Pure.
pub fn days_ahead(today: NaiveDate) -> Vec<NaiveDate> {
    (0..=DAYS_AHEAD)
        .map(|n| today + Duration::days(n))
        .collect()
}

/// The first day whose partition [`drop_expired`] keeps whatever it holds:
/// a partition is a candidate only when its day ended on or before this.
/// Pure.
pub fn retention_cutoff(today: NaiveDate, retention_days: u32) -> NaiveDate {
    today - Duration::days(i64::from(retention_days))
}

/// Creates the partitions of [`days_ahead`] that do not exist yet; returns
/// how many it created.
pub async fn ensure_ahead(ddl: &DbPool, today: NaiveDate) -> Result<u32, AppError> {
    let mut created = 0;
    for day in days_ahead(today) {
        let name = partition_name(day);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_class c
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = current_schema() AND c.relname = $1
             )",
        )
        .bind(&name)
        .fetch_one(ddl)
        .await
        .map_err(AppError::internal)?;
        if exists {
            continue;
        }
        // The bounds are dates this function computed, never request data.
        // DDL takes no bind parameters, so the attach below has PostgreSQL's
        // format() quote them.
        let from = format!("{day} 00:00:00+00");
        let to = format!("{} 00:00:00+00", day + Duration::days(1));
        let mut tx = attome_db::tx::begin(ddl).await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        // Built beside the table and attached, so rows of this day that
        // landed in the default partition move into it first.
        sqlx::query(&format!(
            r#"CREATE TABLE {} (LIKE "{TABLE}" INCLUDING DEFAULTS INCLUDING CONSTRAINTS)"#,
            attome_db::ident::quote_ident(&name)
        ))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(&format!(
            r#"WITH moved AS (
                   DELETE FROM "{TABLE}_default"
                    WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
                RETURNING *
               )
               INSERT INTO {} SELECT * FROM moved"#,
            attome_db::ident::quote_ident(&name)
        ))
        .bind(&from)
        .bind(&to)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let attach: String = sqlx::query_scalar(
            "SELECT format('ALTER TABLE %I ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)', \
                    $1::text, $2::text, $3::text, $4::text)",
        )
        .bind(TABLE)
        .bind(&name)
        .bind(&from)
        .bind(&to)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(&attach)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        tx.commit().await.map_err(AppError::internal)?;
        created += 1;
    }
    Ok(created)
}

/// Drops each daily partition whose day ended on or before
/// [`retention_cutoff`] and that holds no event the workflow consumer has
/// not processed and none past the slowest active cursor. A day held back
/// is logged and tried again on a later run. Returns the partitions dropped.
pub async fn drop_expired(
    ddl: &DbPool,
    today: NaiveDate,
    retention_days: u32,
) -> Result<Vec<String>, AppError> {
    let cutoff = retention_cutoff(today, retention_days)
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| AppError::internal("midnight is a valid time"))?
        .and_utc();
    let candidates =
        crate::partition_maintenance::list_archive_candidates(ddl, TABLE, cutoff).await?;
    let mut dropped = Vec::new();
    for candidate in candidates {
        let name = candidate.partition_name;
        if !attome_db::ident::is_identifier(&name) {
            continue;
        }
        let mut tx = attome_db::tx::begin(ddl).await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(&format!(r#"LOCK TABLE "{name}" IN ACCESS EXCLUSIVE MODE"#))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let still_needed: bool = sqlx::query_scalar(&format!(
            r#"SELECT EXISTS (
                   SELECT 1 FROM {} e
                    WHERE e.processed_at IS NULL
                       OR e.commit_xid > COALESCE(
                              (SELECT MIN(last_commit_xid) FROM change_consumer_cursor
                                WHERE status = 'active'),
                              e.commit_xid
                          )
               )"#,
            attome_db::ident::quote_ident(&name)
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if still_needed {
            tx.rollback().await.map_err(AppError::internal)?;
            tracing::warn!(
                partition = %name,
                "change feed: a day past retention still holds events a consumer has not \
                 finished; kept until it has"
            );
            continue;
        }
        sqlx::query(&format!(
            "DROP TABLE {}",
            attome_db::ident::quote_ident(&name)
        ))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        tx.commit().await.map_err(AppError::internal)?;
        dropped.push(name);
    }
    Ok(dropped)
}

/// Deletes consumers' applied rows ([`super::claim_apply`]) whose event no
/// longer exists, in bounded batches; returns how many.
pub async fn prune_applied(db: &DbPool) -> Result<u64, AppError> {
    let mut total = 0u64;
    loop {
        let deleted = sqlx::query(
            "DELETE FROM change_consumer_applied a \
              WHERE (a.consumer, a.event_id) IN ( \
                  SELECT g.consumer, g.event_id FROM change_consumer_applied g \
                   WHERE NOT EXISTS ( \
                       SELECT 1 FROM entity_change_event e WHERE e.id = g.event_id \
                   ) \
                   LIMIT $1 \
              )",
        )
        .bind(APPLIED_BATCH)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        total += deleted;
        if deleted < APPLIED_BATCH as u64 {
            return Ok(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("a date")
    }

    #[test]
    fn change_feed_retention_names_a_partition_by_its_day() {
        assert_eq!(
            partition_name(day("2026-10-28")),
            "entity_change_event_d20261028"
        );
    }

    #[test]
    fn change_feed_retention_creates_today_and_three_days_ahead() {
        assert_eq!(
            days_ahead(day("2026-12-30")),
            vec![
                day("2026-12-30"),
                day("2026-12-31"),
                day("2027-01-01"),
                day("2027-01-02"),
            ]
        );
    }

    #[test]
    fn change_feed_retention_cutoff_follows_the_clock() {
        assert_eq!(retention_cutoff(day("2026-10-28"), 14), day("2026-10-14"));
        assert_eq!(retention_cutoff(day("2026-03-01"), 1), day("2026-02-28"));
    }
}
