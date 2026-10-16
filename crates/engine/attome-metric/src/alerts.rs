//! Metric alerts (roadmap P11-T1): after each snapshot, a metric whose status
//! got worse (`ok` to `warn` or `crit`, `warn` to `crit`) notifies its owner
//! and steward once. The same status again is not a new crossing, so a metric
//! that stays red does not repeat itself every period; a failed snapshot is
//! not a status and is skipped. `alerts_snoozed_until` on the metric
//! definition silences it until that day.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use uuid::Uuid;

/// How bad a status is; `None` for one that is not a threshold status.
fn rank(status: &str) -> Option<u8> {
    match status {
        "ok" => Some(0),
        "warn" => Some(1),
        "crit" => Some(2),
        _ => None,
    }
}

/// The status a metric has crossed into, when it got worse since the
/// previous threshold status (`None` before the first one counts as `ok`).
pub fn crossing<'a>(previous: Option<&str>, current: &'a str) -> Option<&'a str> {
    let now = rank(current)?;
    let before = previous.and_then(rank).unwrap_or(0);
    (now > before).then_some(current)
}

/// Whether alerts are snoozed on `today`.
pub fn snoozed(snoozed_until: Option<NaiveDate>, today: NaiveDate) -> bool {
    snoozed_until.is_some_and(|until| today <= until)
}

/// Notifies the metric's owner and steward when its newest snapshot crossed
/// into a worse status. Never fails the snapshot: a notification error is
/// logged.
pub async fn after_snapshot(state: &EngineState, metric_id: Uuid) {
    if let Err(e) = notify_on_crossing(state, metric_id).await {
        tracing::warn!(%metric_id, error = %e, "metric alert: notification failed");
    }
}

async fn notify_on_crossing(state: &EngineState, metric_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    // The two newest threshold statuses, newest first.
    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM metric_snapshot \
         WHERE metric_ref = $1 AND status IN ('ok', 'warn', 'crit') \
         ORDER BY computed_at DESC LIMIT 2",
    )
    .bind(metric_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let Some(current) = statuses.first() else {
        return Ok(());
    };
    let Some(level) = crossing(statuses.get(1).map(String::as_str), current) else {
        return Ok(());
    };
    let metric: Option<(String, Option<Uuid>, Option<Uuid>, Option<NaiveDate>)> = sqlx::query_as(
        "SELECT name, owner_ref, steward_ref, alerts_snoozed_until::date \
             FROM dashboard_metric_definition WHERE id = $1",
    )
    .bind(metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((name, owner, steward, snoozed_until)) = metric else {
        return Ok(());
    };
    if snoozed(snoozed_until, Utc::now().date_naive()) {
        return Ok(());
    }
    let mut recipients: Vec<Uuid> = owner.into_iter().chain(steward).collect();
    recipients.dedup();
    let subject = format!("Metric {name} is now {level}");
    let body = format!(
        "The latest value of {name} crossed its {level} threshold. Open the metric to see the value \
         against its target."
    );
    for user in recipients {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(format!(
                "/xrm/entity/dashboard_metric_definition/{metric_id}"
            )),
            variables: std::collections::HashMap::new(),
            priority: if level == "crit" { "high" } else { "normal" }.to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch(db, &state.base.config.notification, req)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_worsening_status_is_a_crossing() {
        assert_eq!(crossing(None, "warn"), Some("warn"));
        assert_eq!(crossing(Some("ok"), "crit"), Some("crit"));
        assert_eq!(crossing(Some("warn"), "crit"), Some("crit"));
        assert_eq!(
            crossing(Some("warn"), "warn"),
            None,
            "the same status notifies once"
        );
        assert_eq!(
            crossing(Some("crit"), "warn"),
            None,
            "an improvement is not an alert"
        );
        assert_eq!(crossing(None, "ok"), None);
        assert_eq!(crossing(Some("ok"), "failed"), None);
    }

    #[test]
    fn snooze_holds_through_its_last_day() {
        let day = |d| NaiveDate::from_ymd_opt(2026, 10, d).unwrap_or_default();
        assert!(snoozed(Some(day(20)), day(20)));
        assert!(!snoozed(Some(day(20)), day(21)));
        assert!(!snoozed(None, day(1)));
    }
}
