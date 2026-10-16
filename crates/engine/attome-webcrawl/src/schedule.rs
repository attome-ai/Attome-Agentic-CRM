//! Scheduled recrawls (roadmap K6-T3): every hour, each website source on
//! a `daily` or `weekly` schedule whose last crawl is older than its period
//! is queued for one crawl.
//!
//! The source's status is the guard, as for a crawl started by hand: one
//! statement moves the due sources to `pending` and returns them, and their
//! crawl jobs are queued in the same transaction. A source already
//! `pending` or `crawling` is never picked, so a run still going is skipped
//! rather than queued twice. Nothing runs while `webcrawl.enabled` is off.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// How long after its last crawl a source is due again; `None` for one
/// crawled by hand.
pub fn period(schedule: &str) -> Option<Duration> {
    match schedule {
        "daily" => Some(Duration::days(1)),
        "weekly" => Some(Duration::weeks(1)),
        _ => None,
    }
}

/// Whether a source is due at `now`.
pub fn is_due(
    schedule: &str,
    last_crawled: Option<DateTime<Utc>>,
    status: &str,
    now: DateTime<Utc>,
) -> bool {
    if matches!(status, "pending" | "crawling") {
        return false;
    }
    match (period(schedule), last_crawled) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(p), Some(last)) => now - last >= p,
    }
}

/// Queues a crawl for every due source; the number queued.
pub async fn enqueue_due(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    if !state.base.config.webcrawl.enabled {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let due: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE webcrawl_target SET status = 'pending', last_error = NULL, \
             row_version = row_version + 1, updated_at = NOW() \
         WHERE id IN (SELECT id FROM webcrawl_target \
             WHERE is_deleted = FALSE AND status NOT IN ('pending', 'crawling') \
               AND ((schedule = 'daily' AND (last_crawled_at IS NULL \
                       OR last_crawled_at <= $1 - INTERVAL '1 day')) \
                 OR (schedule = 'weekly' AND (last_crawled_at IS NULL \
                       OR last_crawled_at <= $1 - INTERVAL '7 days'))) \
             ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED) \
         RETURNING id",
    )
    .bind(now)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for target_id in &due {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::CrawlWebsite {
                target_id: *target_id,
            },
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(due.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, 6, 0, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn due_by_schedule_and_status() {
        assert!(is_due("daily", Some(at(1)), "crawled", at(2)));
        assert!(!is_due("daily", Some(at(2)), "crawled", at(2)));
        assert!(!is_due("weekly", Some(at(1)), "crawled", at(5)));
        assert!(is_due("weekly", Some(at(1)), "failed", at(8)));
        assert!(is_due("daily", None, "crawled", at(1)), "never crawled");
        assert!(!is_due("manual", None, "crawled", at(1)));
        assert!(
            !is_due("daily", Some(at(1)), "crawling", at(9)),
            "a running crawl is skipped"
        );
        assert!(
            !is_due("daily", Some(at(1)), "pending", at(9)),
            "a queued crawl is skipped"
        );
    }
}
