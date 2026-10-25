//! Y6-T1: lease-based singletons. When several processes run the same
//! singleton loop (the audit chainer on two nodes, say), one row per name in
//! `process_lease` (migration 0249) says who runs it: the holder renews its
//! lease each cycle; the others find it held and wait; when the holder stops
//! renewing (it crashed, or lost the database) the lease expires and the
//! next one to ask takes it over.
//!
//! The lease saves work, it is not the correctness guard: the loops it
//! protects keep their own per-batch locks, so two holders at once (a clock
//! skew, a slow renewal) are wasteful but never wrong. Times are the
//! database's `now()`, so the nodes' clocks do not matter.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};

/// Whether `me` may hold a lease currently held by `holder` until
/// `expires_at`, at `now`: free, already mine, or expired. Pure.
pub fn may_take(
    holder: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
    me: &str,
    now: DateTime<Utc>,
) -> bool {
    match (holder, expires_at) {
        (None, _) | (_, None) => true,
        (Some(h), _) if h == me => true,
        (Some(_), Some(until)) => until <= now,
    }
}

/// Takes or renews `name` for `holder` for `ttl`; `false` while another
/// holder's lease runs. One statement, so two asking at once cannot both
/// win.
pub async fn try_acquire(
    db: &DbPool,
    name: &str,
    holder: &str,
    ttl: std::time::Duration,
) -> Result<bool, AppError> {
    let millis = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
    let won: Option<String> = sqlx::query_scalar(
        "INSERT INTO process_lease (name, holder, expires_at) \
         VALUES ($1, $2, now() + make_interval(secs => $3::double precision / 1000)) \
         ON CONFLICT (name) DO UPDATE \
            SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at, \
                acquired_at = CASE WHEN process_lease.holder = EXCLUDED.holder \
                                   THEN process_lease.acquired_at ELSE now() END \
          WHERE process_lease.holder = EXCLUDED.holder OR process_lease.expires_at <= now() \
         RETURNING holder",
    )
    .bind(name)
    .bind(holder)
    .bind(millis)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(won.is_some())
}

/// Gives `name` up if `holder` holds it, so another can take it at once.
pub async fn release(db: &DbPool, name: &str, holder: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM process_lease WHERE name = $1 AND holder = $2")
        .bind(name)
        .bind(holder)
        .execute(db)
        .await
        .map_err(AppError::internal)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + s, 0).unwrap()
    }

    #[test]
    fn lease_free_mine_or_expired() {
        assert!(may_take(None, None, "a", at(0)), "free");
        assert!(
            may_take(Some("a"), Some(at(30)), "a", at(10)),
            "mine: renew"
        );
        assert!(!may_take(Some("b"), Some(at(30)), "a", at(10)), "held by b");
        assert!(may_take(Some("b"), Some(at(30)), "a", at(30)), "expired");
        assert!(may_take(Some("b"), Some(at(30)), "a", at(31)));
    }
}
