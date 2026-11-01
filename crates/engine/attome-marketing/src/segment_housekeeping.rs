//! Segment housekeeping (roadmap E7-T10): a list nobody has used for
//! [`PAUSE_AFTER_DAYS`] days stops refreshing, and using it again resumes it.
//!
//! - [`pause_unused`] (the `marketing_list_pause_unused` job, nightly) sets
//!   `is_paused` on scheduled and live lists whose `last_used_at` (or, never
//!   used, `created_at`) is older than that. The scheduled refresh and the
//!   live tick skip a paused list.
//! - [`touch`] marks a list used: the list read routes (count, sample,
//!   explain, past and current members, usage) call it, setting
//!   `last_used_at` and clearing `is_paused`. It writes at most once an hour
//!   per list, and leaves `row_version` alone so reading a list never makes
//!   an editor's `If-Match` stale.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// Days without use after which a list stops refreshing.
pub const PAUSE_AFTER_DAYS: i64 = 90;
/// The nightly job's registered name.
pub const PAUSE_JOB: &str = "marketing_list_pause_unused";

/// Whether a list last used at `last_used` (or created at `created`) is due
/// to pause at `now`. A manual list never refreshes on its own, so it never
/// pauses. Pure.
pub fn due_for_pause(
    refresh_mode: &str,
    last_used: Option<DateTime<Utc>>,
    created: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    refresh_mode != "manual"
        && last_used
            .or(created)
            .is_some_and(|at| at < now - Duration::days(PAUSE_AFTER_DAYS))
}

/// Pauses every refreshing list unused for [`PAUSE_AFTER_DAYS`] days; the
/// number paused. Nothing before the marketing pack is installed.
pub async fn pause_unused(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('marketing_list') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let done = sqlx::query(
        "UPDATE marketing_list SET is_paused = true \
          WHERE (is_active IS NULL OR is_active = true) \
            AND COALESCE(is_paused, false) = false \
            AND COALESCE(refresh_mode, 'manual') <> 'manual' \
            AND COALESCE(last_used_at, created_at) < $1",
    )
    .bind(now - Duration::days(PAUSE_AFTER_DAYS))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() > 0 {
        tracing::info!(
            paused = done.rows_affected(),
            "marketing lists paused after 90 days unused"
        );
    }
    Ok(done.rows_affected())
}

/// Marks `list` used now and resumes it if paused. A failure is logged: a
/// read must not fail because its bookkeeping did.
pub async fn touch(state: &EngineState, list: Uuid) {
    let result = sqlx::query(
        "UPDATE marketing_list SET last_used_at = now(), is_paused = false \
          WHERE id = $1 \
            AND (last_used_at IS NULL OR last_used_at < now() - INTERVAL '1 hour' \
                 OR COALESCE(is_paused, false))",
    )
    .bind(list)
    .execute(&state.base.db)
    .await;
    if let Err(error) = result {
        tracing::warn!(%list, %error, "marketing list use not recorded");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_list_selected_for_pause() {
        let now = DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let days_ago = |d: i64| Some(now - Duration::days(d));
        assert!(due_for_pause("scheduled", days_ago(91), None, now));
        assert!(!due_for_pause("scheduled", days_ago(89), None, now));
        assert!(
            due_for_pause("live", None, days_ago(120), now),
            "never used"
        );
        assert!(!due_for_pause("manual", days_ago(400), None, now));
        assert!(!due_for_pause("scheduled", None, None, now));
    }
}
