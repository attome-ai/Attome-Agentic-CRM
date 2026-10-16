//! Session activity (roadmap Q8-T3): when a cookie session last did
//! something real, for the idle timeout. A request records its refresh
//! family's "seen now" into one Redis hash field (repeated requests overwrite
//! it), and a once-a-minute flush folds the whole buffer into one bulk
//! `UPDATE refresh_token SET last_activity_at`, so activity costs no write
//! per request. Background polling (`x-attome-background: 1`) is not
//! activity. The buffer is observational: losing it only makes the recorded
//! activity up to a minute older (guidelines §5).

use std::time::Duration;

use attome_cache::{Store, write_coalesce};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

const HASH_KEY: &str = "attome-server:session-activity";

/// A buffer nobody flushes for a day is not worth keeping.
const BUFFER_TTL_SECS: i64 = 86_400;

/// How often the buffer is folded into Postgres.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// The header the web client's pollers send.
pub const BACKGROUND_HEADER: &str = "x-attome-background";

/// Whether a request is background polling rather than a person's action.
pub fn is_background(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(BACKGROUND_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1")
}

/// Records that the session family `family_id` was active at `at`.
/// Best-effort: callers log and continue.
pub async fn record(redis: &Store, family_id: Uuid, at: DateTime<Utc>) -> Result<(), AppError> {
    write_coalesce::set_with_ttl(
        redis,
        HASH_KEY,
        &family_id.to_string(),
        &at.to_rfc3339(),
        BUFFER_TTL_SECS,
    )
    .await
}

/// Drains the buffer into one bulk update of the families' live tokens.
/// Returns how many families were written.
pub async fn flush(db: &DbPool, redis: &Store) -> Result<usize, AppError> {
    let drained = write_coalesce::drain(redis, HASH_KEY).await?;
    let mut ids = Vec::with_capacity(drained.len());
    let mut ats = Vec::with_capacity(drained.len());
    for (field, value) in drained {
        let (Ok(id), Ok(at)) = (field.parse::<Uuid>(), DateTime::parse_from_rfc3339(&value)) else {
            tracing::warn!("session_activity: dropping a malformed buffer entry");
            continue;
        };
        ids.push(id);
        ats.push(at.with_timezone(&Utc));
    }
    if ids.is_empty() {
        return Ok(0);
    }
    sqlx::query(
        "UPDATE refresh_token AS t \
            SET last_activity_at = GREATEST(COALESCE(t.last_activity_at, v.at), v.at) \
           FROM UNNEST($1::uuid[], $2::timestamptz[]) AS v(id, at) \
          WHERE t.family_id = v.id AND t.used_at IS NULL AND t.revoked_at IS NULL",
    )
    .bind(&ids)
    .bind(&ats)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(ids.len())
}

/// The once-a-minute flush loop: process-lifetime supervision, started at
/// boot next to the API-key touch flush.
pub fn spawn_flush_scheduler(db: DbPool, redis: Store) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FLUSH_INTERVAL).await;
            match flush(&db, &redis).await {
                Ok(0) => {}
                Ok(count) => tracing::debug!(count, "session_activity: flushed"),
                Err(e) => tracing::warn!(error = %e, "session_activity: flush failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_requests_are_not_activity() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(!is_background(&headers));
        headers.insert(BACKGROUND_HEADER, axum::http::HeaderValue::from_static("1"));
        assert!(is_background(&headers));
        headers.insert(BACKGROUND_HEADER, axum::http::HeaderValue::from_static("0"));
        assert!(!is_background(&headers));
    }
}
