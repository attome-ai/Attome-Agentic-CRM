//! The marketing-to-sales hand-off SLA (roadmap E9-T7): a lead handed to
//! sales must be accepted or returned within the programme's business hours
//! (`sla_business_hours`, 8 by default), counted on the working calendar.
//! Every five minutes, hand-offs past due become `overdue` and the
//! assignee's manager (the holders of the parent position of any position
//! the assignee holds) is notified, once: the status change is the claim.
//! Only programmes with `sla_enabled` take part.

use std::collections::HashSet;

use attome_calendar::{BusinessCalendar, TimeRange};
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc, Weekday};
use serde::Serialize;
use uuid::Uuid;

/// The hours to decide when the programme sets none.
pub const DEFAULT_SLA_HOURS: f64 = 8.0;

/// The working calendar used until a programme names its own: Sunday to
/// Thursday, 09:00 to 17:00, Riyadh time.
pub fn default_calendar() -> Result<BusinessCalendar, AppError> {
    let days: HashSet<Weekday> = [
        Weekday::Sun,
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
    ]
    .into();
    let hours = TimeRange::try_new(9 * 60, 17 * 60)
        .map_err(|e| AppError::internal(format!("calendar hours: {e}")))?;
    BusinessCalendar::simple(chrono_tz::Asia::Riyadh, days, hours)
        .map_err(|e| AppError::internal(format!("calendar: {e}")))
}

/// When a hand-off made at `start` must be decided.
pub fn due_at(
    calendar: &BusinessCalendar,
    start: DateTime<Utc>,
    hours: Option<f64>,
) -> Result<DateTime<Utc>, AppError> {
    let hours = hours
        .filter(|h| h.is_finite() && *h > 0.0)
        .unwrap_or(DEFAULT_SLA_HOURS);
    let duration = Duration::seconds((hours * 3600.0).round() as i64);
    calendar
        .add_business_duration(start, duration)
        .map_err(|e| AppError::Validation(format!("cannot place the hand-off due time: {e}")))
}

/// Marks overdue hand-offs and notifies the assignees' managers; the number
/// marked.
pub async fn sweep_overdue(
    db: &attome_db::DbPool,
    notification: &attome_config::NotificationSection,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('marketing_nurture_program') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let overdue: Vec<(Uuid, Option<Uuid>, Uuid)> = sqlx::query_as(
        "WITH due AS ( \
             SELECT h.id FROM marketing_handoff h \
             JOIN marketing_nurture_program p ON p.id = h.program_id \
             WHERE h.status = 'pending' AND h.due_at <= $1 \
               AND COALESCE(p.sla_enabled, false) = true \
             ORDER BY h.due_at LIMIT 500 FOR UPDATE OF h SKIP LOCKED) \
         UPDATE marketing_handoff h SET status = 'overdue' FROM due WHERE h.id = due.id \
         RETURNING h.id, h.assigned_to, h.person_id",
    )
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (handoff, assignee, person) in &overdue {
        let Some(assignee) = assignee else { continue };
        let managers: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT mgr.user_ref FROM user_account_mm_position own \
             JOIN position pos ON pos.id = own.position_ref AND pos.is_deleted = false \
             JOIN user_account_mm_position mgr \
                 ON mgr.position_ref = pos.parent_position_ref AND mgr.is_deleted = false \
             JOIN user_account u ON u.id = mgr.user_ref \
             WHERE own.user_ref = $1 AND own.is_deleted = false \
               AND (u.is_active IS NULL OR u.is_active = true)",
        )
        .bind(assignee)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for manager in managers {
            let request = attome_notification::dispatch::DispatchRequest {
                template_key: None,
                locale: "en".to_string(),
                recipient_user_ref: Some(manager),
                is_global: false,
                organization_ref: None,
                channels: None,
                subject: Some("A marketing hand-off is overdue".to_owned()),
                body_html: None,
                body_text: Some(
                    "A lead handed from marketing to your team was not accepted or returned in \
                     time."
                        .to_owned(),
                ),
                route: Some(format!("/xrm/entity/lead/{person}")),
                variables: std::collections::HashMap::new(),
                priority: "high".to_string(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            if let Err(e) =
                attome_notification::dispatch::create_dispatch(db, notification, request).await
            {
                tracing::warn!(%handoff, %manager, error = %e, "hand-off SLA: notification failed");
            }
        }
    }
    Ok(overdue.len() as u64)
}

/// How hand-offs went over a period.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Rates {
    pub accepted: i64,
    pub returned: i64,
    pub overdue: i64,
    /// Median minutes from hand-off to decision; `None` before any decision.
    pub median_minutes_to_decision: Option<f64>,
}

/// Hand-off outcomes of a programme created in `[from, to)`.
pub async fn rates(
    db: &attome_db::DbPool,
    program: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Rates, AppError> {
    let (accepted, returned, overdue, median): (i64, i64, i64, Option<f64>) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE status = 'accepted'), \
                COUNT(*) FILTER (WHERE status = 'returned'), \
                COUNT(*) FILTER (WHERE status = 'overdue'), \
                percentile_cont(0.5) WITHIN GROUP \
                    (ORDER BY EXTRACT(EPOCH FROM (decided_at - created_at)) / 60.0) \
                    FILTER (WHERE decided_at IS NOT NULL) \
         FROM marketing_handoff WHERE program_id = $1 AND created_at >= $2 AND created_at < $3",
    )
    .bind(program)
    .bind(from)
    .bind(to)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Rates {
        accepted,
        returned,
        overdue,
        median_minutes_to_decision: median,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone};

    #[test]
    fn due_date_skips_weekend() {
        let calendar = default_calendar().unwrap_or_else(|e| panic!("{e}"));
        // Friday 16 October 2026, 16:00 in Riyadh (13:00 UTC).
        let start = Utc
            .with_ymd_and_hms(2026, 10, 16, 13, 0, 0)
            .single()
            .unwrap_or_default();
        let due = due_at(&calendar, start, Some(8.0)).unwrap_or_else(|e| panic!("{e}"));
        let local = due.with_timezone(&chrono_tz::Asia::Riyadh);
        assert_eq!(local.weekday(), Weekday::Sun, "{local}");
        assert_eq!(local.date_naive().day(), 18);
    }

    #[test]
    fn no_hours_means_the_default() {
        let calendar = default_calendar().unwrap_or_else(|e| panic!("{e}"));
        // Sunday 18 October 2026, 10:00 Riyadh.
        let start = Utc
            .with_ymd_and_hms(2026, 10, 18, 7, 0, 0)
            .single()
            .unwrap_or_default();
        assert_eq!(
            due_at(&calendar, start, None).ok(),
            due_at(&calendar, start, Some(DEFAULT_SLA_HOURS)).ok()
        );
        assert_eq!(
            due_at(&calendar, start, Some(2.0)).ok(),
            Some(start + Duration::hours(2))
        );
    }
}
