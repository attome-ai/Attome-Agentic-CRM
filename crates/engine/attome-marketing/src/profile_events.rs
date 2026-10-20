//! Profile events (roadmap E23-T1): what a known contact or an anonymous
//! visitor did, kept in the monthly-partitioned `profile_event` table
//! (migration 0167). The partition create-ahead job keeps the coming months
//! ready; [`apply_retention`] drops whole months older than
//! `marketing.profile_event_retention_months` (default 13), so an old event
//! goes with its month and no row is deleted one by one.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Months, Utc};
use serde_json::Value;
use uuid::Uuid;

/// The partitioned table.
pub const TABLE: &str = "profile_event";
/// The default retention, in months.
pub const DEFAULT_RETENTION_MONTHS: u32 = 13;

/// The retention setting, clamped to 1..=120 months.
pub fn retention_months(state: &EngineState) -> u32 {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get("marketing.profile_event_retention_months")
        .and_then(|d| store.resolve(d, None, None).0.as_u64())
        .and_then(|m| u32::try_from(m).ok())
        .unwrap_or(DEFAULT_RETENTION_MONTHS)
        .clamp(1, 120)
}

/// The cut-off for `months` of retention at `now`: partitions ending at or
/// before it are dropped. Pure.
pub fn cutoff(now: DateTime<Utc>, months: u32) -> DateTime<Utc> {
    now.checked_sub_months(Months::new(months)).unwrap_or(now)
}

/// Records one event. `contact` or `anonymous` must be given.
pub async fn record(
    db: &DbPool,
    contact: Option<Uuid>,
    anonymous: Option<&str>,
    kind: &str,
    at: DateTime<Utc>,
    properties: &Value,
) -> Result<Uuid, AppError> {
    if contact.is_none() && anonymous.is_none_or(|a| a.trim().is_empty()) {
        return Err(AppError::Validation(
            "a profile event needs a contact or an anonymous id".into(),
        ));
    }
    if kind.trim().is_empty() || kind.len() > 100 {
        return Err(AppError::Validation("kind is 1 to 100 characters".into()));
    }
    sqlx::query_scalar(
        "INSERT INTO profile_event (contact_id, anonymous_id, kind, at, properties) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(contact)
    .bind(anonymous.map(str::trim))
    .bind(kind.trim())
    .bind(at)
    .bind(properties)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Drops the months past retention. Returns the partitions dropped.
pub async fn apply_retention(state: &EngineState) -> Result<u32, AppError> {
    let db = &state.base.db_migrator;
    let cutoff = cutoff(Utc::now(), retention_months(state));
    let candidates =
        attome_core::partition_maintenance::list_archive_candidates(db, TABLE, cutoff).await?;
    let mut dropped = 0;
    for candidate in candidates {
        attome_core::partition_maintenance::detach_partition(db, TABLE, &candidate.partition_name)
            .await?;
        attome_core::partition_maintenance::drop_detached_partition(db, &candidate.partition_name)
            .await?;
        tracing::info!(partition = %candidate.partition_name, "profile events: month past retention dropped");
        dropped += 1;
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn thirteen_months_back_is_the_cutoff() {
        let now = Utc.with_ymd_and_hms(2026, 10, 20, 3, 0, 0).unwrap();
        assert_eq!(
            cutoff(now, 13),
            Utc.with_ymd_and_hms(2025, 9, 20, 3, 0, 0).unwrap()
        );
    }
}
