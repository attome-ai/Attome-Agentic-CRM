//! E14-T11: how long tracking data is kept, what an erasure removes, and the
//! records-of-processing entry.
//!
//! **Retention.** [`roll_up_and_prune`] (the nightly [`JOB`]) first rolls
//! each site's page views older than its `retention_days` (default
//! [`DEFAULT_RETENTION_DAYS`]) into `marketing_web_daily` (views and
//! distinct sessions per day, page and campaign), then drops whole monthly
//! partitions of `marketing_web_event` whose last day is past the longest
//! retention of any site, so no event is deleted one by one and no month is
//! dropped before every site's days in it were rolled up. A site with a
//! shorter retention than another keeps its raw events until the month
//! passes the longest one. Sessions past their site's retention are
//! deleted (a few thousand a night). The rollup is idempotent: a rerun
//! writes the same totals.
//!
//! Events of a site that no longer exists are not rolled up; they go with
//! their month.
//!
//! **Erasure.** [`TrackingErasure`] (an `attome_core::erasure_hook`) deletes
//! an erased contact's or lead's sessions, every session of the same
//! visitors, their events and their visit summaries, in the erasure's
//! transaction. Daily totals hold no person and stay.
//!
//! **Records of processing.** While `marketing.tracking` is on and the
//! privacy pack is installed, the job makes sure a `processing_activity`
//! named [`ACTIVITY_NAME`] exists (a draft, owned by whoever set up the
//! first tracked site) for the privacy owner to review.

use attome_core::EngineState;
use attome_core::erasure_hook::{ErasureFuture, ErasureHook};
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// The job's name.
pub const JOB: &str = "marketing_web_tracking_retention";
/// The partitioned events table.
pub const TABLE: &str = "marketing_web_event";
/// A site's retention when it names none.
pub const DEFAULT_RETENTION_DAYS: i32 = 395;
/// The name of the records-of-processing entry.
pub const ACTIVITY_NAME: &str = "Website tracking";
/// Sessions deleted per site per run.
const SESSION_BATCH: i64 = 5_000;

/// What one run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionSummary {
    /// Daily total rows written or rewritten.
    pub daily_rows: u64,
    /// Monthly partitions dropped.
    pub partitions_dropped: u32,
    /// Sessions deleted.
    pub sessions_deleted: u64,
    /// Whether the records-of-processing entry was created this run.
    pub activity_created: bool,
}

/// A site's retention in days, clamped to 30..=3650. Pure.
pub fn retention_days(configured: Option<i32>) -> i32 {
    configured
        .filter(|d| *d > 0)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
        .clamp(30, 3650)
}

/// The first instant past retention is `now` less `days`, at midnight UTC:
/// whole days before it are rolled up. Pure.
pub fn cutoff(now: DateTime<Utc>, days: i32) -> DateTime<Utc> {
    let day = now.date_naive() - chrono::Duration::days(i64::from(days));
    day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc()
}

/// Rolls up, drops and prunes; see the module doc.
pub async fn roll_up_and_prune(state: &EngineState) -> Result<RetentionSummary, AppError> {
    let db = &state.base.db;
    let mut summary = RetentionSummary::default();
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('marketing_tracked_site') IS NOT NULL \
            AND to_regclass('marketing_web_event') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(summary);
    }
    let sites: Vec<(String, Option<i32>)> = sqlx::query_as(
        "SELECT site_key, retention_days::int4 FROM marketing_tracked_site \
          WHERE site_key IS NOT NULL ORDER BY site_key",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let mut longest = DEFAULT_RETENTION_DAYS;
    for (site_key, days) in &sites {
        let days = retention_days(*days);
        longest = longest.max(days);
        let cut = cutoff(now, days);
        summary.daily_rows += roll_up(state, site_key, cut).await?;
        summary.sessions_deleted += sqlx::query(
            "DELETE FROM marketing_web_session WHERE id IN ( \
                 SELECT id FROM marketing_web_session \
                  WHERE site_key = $1 AND last_seen_at < $2 LIMIT $3)",
        )
        .bind(site_key)
        .bind(cut)
        .bind(SESSION_BATCH)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    summary.partitions_dropped = drop_months(state, cutoff(now, longest)).await?;
    summary.activity_created = ensure_activity(state).await?;
    Ok(summary)
}

/// Page views of `site_key` before `cut`, from the day after its last
/// rolled-up day, into daily totals. Rows written.
async fn roll_up(state: &EngineState, site_key: &str, cut: DateTime<Utc>) -> Result<u64, AppError> {
    let db = &state.base.db;
    let last: Option<NaiveDate> =
        sqlx::query_scalar("SELECT max(day) FROM marketing_web_daily WHERE site_key = $1")
            .bind(site_key)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    // None: nothing rolled up yet, so from the first event.
    let from = last.map(|d| {
        (d + chrono::Duration::days(1))
            .and_hms_opt(0, 0, 0)
            .unwrap_or_default()
            .and_utc()
    });
    if from.is_some_and(|f| f >= cut) {
        return Ok(0);
    }
    let written = sqlx::query(
        "INSERT INTO marketing_web_daily AS d (site_key, day, url, utm_campaign, views, sessions) \
         SELECT e.site_key, (e.occurred_at AT TIME ZONE 'UTC')::date, e.url, \
                COALESCE(s.utm_campaign, ''), count(*)::int4, count(DISTINCT e.session_id)::int4 \
           FROM marketing_web_event e \
           LEFT JOIN marketing_web_session s ON s.id = e.session_id \
          WHERE e.site_key = $1 AND e.kind = 'page_view' AND e.url IS NOT NULL \
            AND ($2::timestamptz IS NULL OR e.occurred_at >= $2) AND e.occurred_at < $3 \
          GROUP BY 1, 2, 3, 4 \
         ON CONFLICT (site_key, day, url, utm_campaign) DO UPDATE \
            SET views = EXCLUDED.views, sessions = EXCLUDED.sessions",
    )
    .bind(site_key)
    .bind(from)
    .bind(cut)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(written)
}

/// Drops the months of events ending at or before `cut`. Partitions dropped.
async fn drop_months(state: &EngineState, cut: DateTime<Utc>) -> Result<u32, AppError> {
    let db = &state.base.db_migrator;
    let candidates =
        attome_core::partition_maintenance::list_archive_candidates(db, TABLE, cut).await?;
    let mut dropped = 0;
    for candidate in candidates {
        attome_core::partition_maintenance::detach_partition(db, TABLE, &candidate.partition_name)
            .await?;
        attome_core::partition_maintenance::drop_detached_partition(db, &candidate.partition_name)
            .await?;
        tracing::info!(partition = %candidate.partition_name, "web events: month past retention dropped");
        dropped += 1;
    }
    Ok(dropped)
}

/// The records-of-processing entry for tracking, made once while tracking
/// is on. True when it was created now.
async fn ensure_activity(state: &EngineState) -> Result<bool, AppError> {
    if !state
        .feature_flags()
        .is_on_for_deployment("marketing.tracking")
    {
        return Ok(false);
    }
    let registry = state.entities.load();
    let Some(meta) = registry.get("processing_activity") else {
        return Ok(false);
    };
    let fields: std::collections::HashSet<String> =
        meta.attrs.iter().map(|a| a.logicalname.clone()).collect();
    drop(registry);
    let db = &state.base.db;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM processing_activity WHERE name = $1)")
            .bind(ACTIVITY_NAME)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT COALESCE(owner_ref, created_by) FROM marketing_tracked_site \
          WHERE (is_active IS NULL OR is_active = true) ORDER BY created_at, id LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(Some(owner)) = owner else {
        return Ok(false);
    };
    let mut values = Map::new();
    for (key, value) in activity_values() {
        if fields.contains(key) {
            values.insert(key.to_owned(), value);
        }
    }
    let ctx = state.base.security.resolve_strict(owner).await?;
    attome_records::entity_crud::create_record_for(
        state,
        &ctx,
        owner,
        "processing_activity",
        Value::Object(values),
    )
    .await?;
    tracing::info!("website tracking: records-of-processing entry created");
    Ok(true)
}

/// The entry's values. Pure.
pub fn activity_values() -> Vec<(&'static str, Value)> {
    vec![
        ("name", json!(ACTIVITY_NAME)),
        (
            "purpose",
            json!(
                "Measuring visits to the organisation's websites and showing a known \
                   visitor's visits on their record (E14)."
            ),
        ),
        ("lawful_basis", json!("consent")),
        (
            "data_categories",
            json!(
                "Pages viewed, time on page, referrer and campaign, device class, country, \
                   the IP address with its last part removed, and the likely company."
            ),
        ),
        ("special_categories", json!(false)),
        (
            "data_subjects",
            json!("Website visitors, contacts and leads."),
        ),
        ("recipients", json!("None outside the organisation.")),
        ("cross_border", json!(false)),
        (
            "retention_period",
            json!(
                "Each site's retention_days (395 by default); after it, daily totals \
                   without people only."
            ),
        ),
        (
            "security_measures",
            json!(
                "Collected only after consent; IP addresses truncated before storage; \
                   staff, office and bot traffic dropped; erased with the person."
            ),
        ),
        ("status", json!("draft")),
    ]
}

/// An erased person's tracking: their sessions, their visitors' other
/// sessions, those sessions' events and their visit summaries.
#[derive(Debug)]
pub struct TrackingErasure;

impl ErasureHook for TrackingErasure {
    fn name(&self) -> &'static str {
        "marketing_tracking"
    }

    fn erase<'a>(
        &'a self,
        conn: &'a mut sqlx::PgConnection,
        entity: &'a str,
        record_id: Uuid,
    ) -> ErasureFuture<'a> {
        Box::pin(async move {
            if entity != "contact" && entity != "lead" {
                return Ok(0);
            }
            let installed: bool =
                sqlx::query_scalar("SELECT to_regclass('marketing_web_session') IS NOT NULL")
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(AppError::internal)?;
            if !installed {
                return Ok(0);
            }
            let sessions: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM marketing_web_session WHERE visitor_id IN ( \
                     SELECT visitor_id FROM marketing_web_session \
                      WHERE contact_ref = $1 OR lead_ref = $1)",
            )
            .bind(record_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            let mut removed = 0;
            if !sessions.is_empty() {
                removed +=
                    sqlx::query("DELETE FROM marketing_web_event WHERE session_id = ANY($1)")
                        .bind(&sessions)
                        .execute(&mut *conn)
                        .await
                        .map_err(AppError::internal)?
                        .rows_affected();
                removed += sqlx::query("DELETE FROM marketing_web_session WHERE id = ANY($1)")
                    .bind(&sessions)
                    .execute(&mut *conn)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
            }
            let summaries: bool =
                sqlx::query_scalar("SELECT to_regclass('marketing_visit_summary') IS NOT NULL")
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(AppError::internal)?;
            if summaries {
                let column = if entity == "contact" {
                    "contact_ref"
                } else {
                    "lead_ref"
                };
                removed += sqlx::query(&format!(
                    "DELETE FROM marketing_visit_summary WHERE {} = $1",
                    attome_core::quote_ident(column)
                ))
                .bind(record_id)
                .execute(&mut *conn)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
            }
            Ok(removed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn retention_defaults_and_clamps() {
        assert_eq!(retention_days(None), DEFAULT_RETENTION_DAYS);
        assert_eq!(retention_days(Some(0)), DEFAULT_RETENTION_DAYS);
        assert_eq!(retention_days(Some(7)), 30);
        assert_eq!(retention_days(Some(90)), 90);
        assert_eq!(retention_days(Some(100_000)), 3650);
    }

    #[test]
    fn the_cutoff_is_midnight_days_back() {
        let now = Utc.with_ymd_and_hms(2026, 11, 2, 15, 30, 0).unwrap();
        assert_eq!(
            cutoff(now, 30),
            Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn the_entry_is_a_draft_on_consent() {
        let values: std::collections::HashMap<_, _> = activity_values().into_iter().collect();
        assert_eq!(values["name"], json!(ACTIVITY_NAME));
        assert_eq!(values["lawful_basis"], json!("consent"));
        assert_eq!(values["status"], json!("draft"));
    }
}
