//! Y12-T9: old structure is removed only after a waiting period and once
//! every node runs the metadata that no longer uses it.
//!
//! Deleting a field and swapping a large retype into place used to drop the
//! old column in the same transaction. Now they **retire** it
//! ([`retire_column_in_tx`]): its `NOT NULL` and default are lifted (so
//! writes that no longer name it still succeed), the constraints and
//! indexes on it are dropped as a drop would have dropped them (so the
//! field's own can be made again under their names; a computed column
//! built on it refuses the change, as a drop would), and it is renamed to
//! `__retired_<id>`, recorded in `schema_retired_column` (migration 0363)
//! with the metadata version current at the time. Its values stay where
//! they were for the period, which is also what a rollback needs.
//!
//! The daily [`JOB`] drops each retired column once [`ready_to_contract`]:
//! the period (`records.contract_period_hours`, 168 by default) has passed,
//! and every node seen in the last day ([`NODE_WINDOW_HOURS`], by its
//! latest `metadata_node_switch` row) is on a version at or above the one
//! recorded. A retired column recorded with no version (no version was
//! current) waits for the period only. A drop that fails (a lock not
//! granted in time, a dependent object) is logged and tried again the next
//! day; nothing else is touched.

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::field_change::{map_ddl_error, set_ddl_bounds_in_tx};

/// The registered daily job.
pub const JOB: &str = "metadata_contract";

/// The setting that holds the waiting period, in hours.
pub const PERIOD_SETTING: &str = "records.contract_period_hours";

/// The waiting period when the setting is missing.
pub const DEFAULT_PERIOD_HOURS: i64 = 168;

/// A node counts while its latest switch is this recent.
pub const NODE_WINDOW_HOURS: i64 = 24;

/// What a retired column is renamed to.
pub const RETIRED_PREFIX: &str = "__retired_";

/// Retired columns one run looks at.
const BATCH: i64 = 200;

/// The name a retired column takes: the prefix and 20 hex digits of `id`
/// (30 characters, inside PostgreSQL's 63). Pure.
pub fn retired_name(id: Uuid) -> String {
    let hex = id.simple().to_string();
    format!("{RETIRED_PREFIX}{}", &hex[hex.len() - 20..])
}

/// Retires `column` of the entity table `table`, in the caller's
/// transaction (which set the DDL bounds): lifts its `NOT NULL` and default,
/// renames it and records it. Nothing happens when the column is not there.
pub async fn retire_column_in_tx(
    conn: &mut PgConnection,
    table: &str,
    column: &str,
) -> Result<(), AppError> {
    if !super::field_change::column_exists(conn, table, column).await? {
        return Ok(());
    }
    let id = Uuid::now_v7();
    let retired = retired_name(id);
    let (t, c) = (quote_ident(table), quote_ident(column));
    let attnum: i16 = sqlx::query_scalar(
        "SELECT attnum FROM pg_attribute \
          WHERE attrelid = to_regclass($1) AND attname = $2 AND NOT attisdropped",
    )
    .bind(&t)
    .bind(column)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // A computed column built on it would follow the rename and go stale;
    // a drop would have been refused for the same dependency.
    let computed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_depend \
          WHERE classid = 'pg_class'::regclass AND objid = to_regclass($1) AND objsubid <> 0 \
            AND refobjid = to_regclass($1) AND refobjsubid = $2)",
    )
    .bind(&t)
    .bind(attnum)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if computed {
        return Err(AppError::Conflict(
            "a computed field depends on this column; change or remove it first",
        ));
    }
    // What a drop removed with the column goes now, so the field's own
    // constraints and indexes can be made again under their names.
    let constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint \
          WHERE conrelid = to_regclass($1) AND contype <> 'p' AND $2 = ANY(conkey)",
    )
    .bind(&t)
    .bind(attnum)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for name in constraints {
        sqlx::query(&format!(
            "ALTER TABLE {t} DROP CONSTRAINT IF EXISTS {}",
            quote_ident(&name)
        ))
        .execute(&mut *conn)
        .await
        .map_err(map_ddl_error)?;
    }
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT ic.relname::text FROM pg_depend d \
           JOIN pg_class ic ON ic.oid = d.objid AND ic.relkind = 'i' \
          WHERE d.classid = 'pg_class'::regclass AND d.refobjid = to_regclass($1) \
            AND d.refobjsubid = $2",
    )
    .bind(&t)
    .bind(attnum)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for name in indexes {
        sqlx::query(&format!("DROP INDEX IF EXISTS {}", quote_ident(&name)))
            .execute(&mut *conn)
            .await
            .map_err(map_ddl_error)?;
    }
    for sql in [
        format!("ALTER TABLE {t} ALTER COLUMN {c} DROP NOT NULL"),
        format!("ALTER TABLE {t} ALTER COLUMN {c} DROP DEFAULT"),
        format!(
            "ALTER TABLE {t} RENAME COLUMN {c} TO {}",
            quote_ident(&retired)
        ),
    ] {
        sqlx::query(&sql)
            .execute(&mut *conn)
            .await
            .map_err(map_ddl_error)?;
    }
    sqlx::query(
        "INSERT INTO schema_retired_column \
             (id, table_name, column_name, retired_name, metadata_version) \
         VALUES ($1, $2, $3, $4, (SELECT version FROM metadata_current WHERE singleton))",
    )
    .bind(id)
    .bind(table)
    .bind(column)
    .bind(&retired)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Whether a column retired at `retired_at` under `version` may go at
/// `now`: the period has passed and no node in `nodes` (each one's latest
/// version) is behind `version`. Pure.
pub fn ready(
    now: DateTime<Utc>,
    retired_at: DateTime<Utc>,
    period: Duration,
    version: Option<i64>,
    nodes: &[i64],
) -> bool {
    if now - retired_at < period {
        return false;
    }
    match version {
        Some(version) => nodes.iter().all(|node| *node >= version),
        None => true,
    }
}

/// Each node's latest version, for the nodes seen since `since`.
async fn node_versions(db: &DbPool, since: DateTime<Utc>) -> Result<Vec<i64>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT ON (node_id) version FROM metadata_node_switch \
          WHERE node_id IN (SELECT node_id FROM metadata_node_switch WHERE switched_at >= $1) \
          ORDER BY node_id, switched_at DESC, version DESC",
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Whether the retired column `id` may be dropped now (false when it is
/// unknown or already dropped).
pub async fn ready_to_contract(db: &DbPool, id: Uuid, period_hours: i64) -> Result<bool, AppError> {
    let row: Option<(DateTime<Utc>, Option<i64>)> = sqlx::query_as(
        "SELECT retired_at, metadata_version FROM schema_retired_column \
          WHERE id = $1 AND dropped_at IS NULL",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((retired_at, version)) = row else {
        return Ok(false);
    };
    let now = Utc::now();
    let nodes = node_versions(db, now - Duration::hours(NODE_WINDOW_HOURS)).await?;
    Ok(ready(
        now,
        retired_at,
        Duration::hours(period_hours.max(0)),
        version,
        &nodes,
    ))
}

/// One contraction run: drops every retired column that is ready; the
/// number dropped.
pub async fn contract_due(db: &DbPool, period_hours: i64) -> Result<u64, AppError> {
    let due: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, table_name, retired_name FROM schema_retired_column \
          WHERE dropped_at IS NULL AND retired_at <= now() - make_interval(hours => $1::int) \
          ORDER BY retired_at LIMIT $2",
    )
    .bind(i32::try_from(period_hours.max(0)).unwrap_or(i32::MAX))
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut dropped = 0;
    for (id, table, retired) in due {
        if !ready_to_contract(db, id, period_hours).await? {
            continue;
        }
        match drop_retired(db, id, &table, &retired).await {
            Ok(()) => dropped += 1,
            Err(error) => {
                tracing::warn!(%id, %table, %retired, %error, "a retired column was not dropped; tried again tomorrow");
            }
        }
    }
    Ok(dropped)
}

async fn drop_retired(db: &DbPool, id: Uuid, table: &str, retired: &str) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    set_ddl_bounds_in_tx(&mut tx).await?;
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(quote_ident(table))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if exists {
        sqlx::query(&format!(
            "ALTER TABLE {} DROP COLUMN IF EXISTS {}",
            quote_ident(table),
            quote_ident(retired)
        ))
        .execute(&mut *tx)
        .await
        .map_err(map_ddl_error)?;
    }
    sqlx::query("UPDATE schema_retired_column SET dropped_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retired_name_fits_and_is_recognisable() {
        let name = retired_name(Uuid::now_v7());
        assert!(name.starts_with(RETIRED_PREFIX));
        assert_eq!(name.len(), RETIRED_PREFIX.len() + 20);
    }

    #[test]
    fn contraction_waits_for_the_period_and_every_node() {
        let now = Utc::now();
        let week = Duration::hours(168);
        let old = now - Duration::hours(200);
        assert!(
            !ready(now, now - Duration::hours(1), week, Some(5), &[5]),
            "too soon"
        );
        assert!(!ready(now, old, week, Some(5), &[5, 4]), "a node lags");
        assert!(ready(now, old, week, Some(5), &[5, 6]));
        assert!(ready(now, old, week, Some(5), &[]), "no node seen");
        assert!(
            ready(now, old, week, None, &[1]),
            "no version: the period only"
        );
    }
}
