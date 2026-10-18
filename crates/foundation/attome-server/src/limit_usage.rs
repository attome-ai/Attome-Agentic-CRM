//! AA9-T5: how often each limit is hit, and by whom. Every hit adds to the
//! counter `limit_hits_total{limit, principal_kind}` and to a small
//! process-local tally of hits and the peak value seen per (limit, kind,
//! principal); every node flushes its tally into `limit_usage_daily`
//! (migration 0115) every five minutes, so an operator sees which limits
//! bind and for whom before raising one.
//!
//! The tally is observational and rebuildable (guidelines §5): it holds at
//! most [`MAX_KEYS`] principals, after which further principals are folded
//! into one row per (limit, kind) with no principal; a failed flush puts the
//! drained counts back for the next run; a crash loses at most five minutes
//! of counts, never a decision.
//!
//! Hits are recorded where a limit refuses: the rate limiters, the body
//! limit (before sign-in, so its principal is `unknown`), and every
//! `AppError::LimitExceeded` response, which carries a [`LimitHit`] the rate
//! limiter's layer reads on the way out with the caller it already knows.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use attome_db::DbPool;
use attome_types::AppError;
pub use attome_types::error::LimitHit;
use uuid::Uuid;

/// The most principals the tally holds between flushes.
pub const MAX_KEYS: usize = 10_000;

/// How often a node flushes its tally.
pub const FLUSH_EVERY: Duration = Duration::from_secs(300);

/// The principal id a row without one is stored under.
const NO_PRINCIPAL: Uuid = Uuid::nil();

type Key = (String, &'static str, Uuid);

static TALLY: Mutex<Option<HashMap<Key, (i64, i64)>>> = Mutex::new(None);

/// One (limit, principal) row of a flush.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow {
    pub limit_key: String,
    pub principal_kind: &'static str,
    pub principal_id: Uuid,
    pub hits: i64,
    pub peak: i64,
}

fn add(key: Key, hits: i64, peak: i64) {
    let mut guard = TALLY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tally = guard.get_or_insert_with(HashMap::new);
    let key = if tally.contains_key(&key) || tally.len() < MAX_KEYS {
        key
    } else {
        (key.0, key.1, NO_PRINCIPAL)
    };
    let entry = tally.entry(key).or_insert((0, 0));
    entry.0 += hits;
    entry.1 = entry.1.max(peak);
}

/// Records one hit on `limit` by a `principal_kind` caller (`user`,
/// `api_key`, `anonymous` or `unknown`), with the value that hit it (the
/// size asked for, or for a rate the requests counted in its window).
pub fn record_limit_hit(
    limit: &str,
    principal_kind: &'static str,
    principal_id: Option<Uuid>,
    value: i64,
) {
    metrics::counter!(
        "limit_hits_total",
        "limit" => limit.to_owned(),
        "principal_kind" => principal_kind,
    )
    .increment(1);
    add(
        (
            limit.to_owned(),
            principal_kind,
            principal_id.unwrap_or(NO_PRINCIPAL),
        ),
        1,
        value,
    );
}

/// AA9-T7: records how close a caller came to `limit` without being
/// refused (`value`, in the limit's unit), so the daily warning check sees a
/// limit nearing its value before anyone is refused. Counts no hit.
pub fn record_limit_use(
    limit: &str,
    principal_kind: &'static str,
    principal_id: Option<Uuid>,
    value: i64,
) {
    add(
        (
            limit.to_owned(),
            principal_kind,
            principal_id.unwrap_or(NO_PRINCIPAL),
        ),
        0,
        value,
    );
}

/// Empties the tally and answers what it held.
pub fn drain() -> Vec<UsageRow> {
    let mut guard = TALLY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(
            |((limit_key, principal_kind, principal_id), (hits, peak))| UsageRow {
                limit_key,
                principal_kind,
                principal_id,
                hits,
                peak,
            },
        )
        .collect()
}

/// Adds today's `rows` to `limit_usage_daily`, in one transaction.
pub async fn upsert(db: &DbPool, rows: &[UsageRow]) -> Result<(), AppError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = attome_db::tx::begin(db).await?;
    for row in rows {
        sqlx::query(
            "INSERT INTO limit_usage_daily (day, limit_key, principal_kind, principal_id, hits, peak) \
             VALUES ((now() AT TIME ZONE 'UTC')::date, $1, $2, $3, $4, $5) \
             ON CONFLICT (day, limit_key, principal_kind, principal_id) DO UPDATE \
             SET hits = limit_usage_daily.hits + EXCLUDED.hits, \
                 peak = GREATEST(limit_usage_daily.peak, EXCLUDED.peak)",
        )
        .bind(&row.limit_key)
        .bind(row.principal_kind)
        .bind(row.principal_id)
        .bind(row.hits)
        .bind(row.peak)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await
}

/// Flushes the tally; on failure the drained counts go back for the next
/// run. Answers how many rows were written.
pub async fn flush(db: &DbPool) -> Result<usize, AppError> {
    let rows = drain();
    match upsert(db, &rows).await {
        Ok(()) => Ok(rows.len()),
        Err(error) => {
            for row in rows {
                add(
                    (row.limit_key, row.principal_kind, row.principal_id),
                    row.hits,
                    row.peak,
                );
            }
            Err(error)
        }
    }
}

/// Starts this node's flush loop: process-lifetime supervision (guidelines
/// §10); a failed flush is logged and retried on the next tick.
pub fn spawn_flusher(db: DbPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(FLUSH_EVERY);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = flush(&db).await {
                tracing::warn!(%error, "limit usage: flush failed; counts kept for the next run");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hits_add_up_and_peaks_keep_the_largest() {
        let user = Uuid::now_v7();
        record_limit_hit("test.tally", "user", Some(user), 10);
        record_limit_hit("test.tally", "user", Some(user), 40);
        record_limit_hit("test.tally", "anonymous", None, 0);
        let rows: Vec<UsageRow> = drain()
            .into_iter()
            .filter(|r| r.limit_key == "test.tally")
            .collect();
        let mine = rows.iter().find(|r| r.principal_id == user).unwrap();
        assert_eq!((mine.hits, mine.peak), (2, 40));
        let anonymous = rows
            .iter()
            .find(|r| r.principal_kind == "anonymous")
            .unwrap();
        assert_eq!(anonymous.principal_id, NO_PRINCIPAL);
    }
}
