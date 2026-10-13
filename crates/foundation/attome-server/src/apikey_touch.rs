//! `api_key.last_used_at` touch, off the apalis Postgres queue
//! (P-job-system-hardening (b) — was `PlatformJob::TouchApiKey`). Every
//! API-key-authenticated request used to insert (and the worker then
//! update/delete) a durable queue row purely to record a "last used"
//! timestamp nobody needs replay-safe delivery for — real write
//! amplification against Postgres for a MINOR, best-effort value. This
//! coalesces concurrent touches for the same key into one Redis hash field
//! (`attome_cache::write_coalesce`) and periodically folds the whole buffer
//! into one bulk `UPDATE`, so at most one write per flush interval per
//! distinct key reaches Postgres, however many requests touched it in
//! between.
//!
//! Accepted tradeoff (stated, not silent — same reasoning as
//! `xrm_s2s::telemetry`): `api_key.last_used_at` is now accurate to
//! within one flush interval (a fixed 30s — see the `flush_interval` comment
//! next to its callers in `main.rs`/`bin/worker.rs`) instead of real-time.
//! Nothing in this codebase reads that column on a path that needs stronger
//! freshness than that (it's an operator-facing "last seen" value, not used
//! in any auth/authorization decision).

use std::time::Duration;

use attome_cache::{RedisPool, write_coalesce};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

const HASH_KEY: &str = "attome-server:touch:apikey";

/// BCA-43/BCA-F6 — the buffer is a touch record, not durable state: if the
/// flush path never runs again (a worker that stayed down, a deployment whose
/// scheduler was disabled), the old code left the hash in Redis forever. A day
/// is far longer than any outage that still leaves the data meaningful, and the
/// flush applies "latest use" anyway.
const TOUCH_TTL_SECS: i64 = 86_400;

/// Records that `key_id` was used at `at` — coalesced with any other touch
/// for the same key since the last flush (last write wins, which is exactly
/// the desired "most recent use" semantics). Best-effort: callers should log
/// a warning and continue rather than fail the request over this.
pub async fn record_touch(
    redis: &RedisPool,
    key_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(), AppError> {
    write_coalesce::set_with_ttl(
        redis,
        HASH_KEY,
        &key_id.to_string(),
        &at.to_rfc3339(),
        TOUCH_TTL_SECS,
    )
    .await
}

/// Drains the touch buffer and applies every distinct key's latest timestamp
/// in one bulk `UPDATE` (guidelines §14 — no N+1). Returns how many distinct
/// keys were flushed. A malformed field/value pair (should never happen —
/// every writer is `record_touch` above) is logged and skipped rather than
/// failing the whole flush over one bad entry.
pub async fn flush(db: &DbPool, redis: &RedisPool) -> Result<usize, AppError> {
    let drained = write_coalesce::drain(redis, HASH_KEY).await?;
    if drained.is_empty() {
        return Ok(0);
    }

    let mut ids = Vec::with_capacity(drained.len());
    let mut ats = Vec::with_capacity(drained.len());
    for (field, value) in drained {
        let Ok(key_id) = field.parse::<Uuid>() else {
            tracing::warn!("apikey_touch: dropping malformed key id in touch buffer: {field:?}");
            continue;
        };
        let Ok(at) = DateTime::parse_from_rfc3339(&value) else {
            tracing::warn!("apikey_touch: dropping malformed timestamp in touch buffer: {value:?}");
            continue;
        };
        ids.push(key_id);
        ats.push(at.with_timezone(&Utc));
    }
    if ids.is_empty() {
        return Ok(0);
    }

    let count = ids.len();
    sqlx::query(
        r#"
        UPDATE api_key AS k
        SET last_used_at = v.at
        FROM UNNEST($1::uuid[], $2::timestamptz[]) AS v(id, at)
        WHERE k.id = v.id
        "#,
    )
    .bind(&ids)
    .bind(&ats)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    Ok(count)
}

/// Detached `tokio::spawn` loop, same shape as
/// `server::jobs::spawn_partition_maintenance_scheduler` — periodically
/// flushes the touch buffer rather than requiring an operator to remember to
/// call `flush` anywhere. Meant to be started unconditionally at boot (this
/// mechanism has no config gate — API-key auth already runs unconditionally).
pub fn spawn_flush_scheduler(db: DbPool, redis: RedisPool, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match flush(&db, &redis).await {
                Ok(0) => {}
                Ok(count) => tracing::debug!(count, "apikey_touch: flushed last_used_at touches"),
                Err(e) => tracing::warn!(error = %e, "apikey_touch: flush failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_round_trips_through_rfc3339() {
        let at = Utc::now();
        let encoded = at.to_rfc3339();
        let decoded = DateTime::parse_from_rfc3339(&encoded)
            .expect("rfc3339 round trip")
            .with_timezone(&Utc);
        // rfc3339 only carries down to some sub-second precision (fine for a
        // "last used" display value) — compare truncated to seconds instead
        // of asserting bit-for-bit equality with the original.
        assert_eq!(at.timestamp(), decoded.timestamp());
    }
}
