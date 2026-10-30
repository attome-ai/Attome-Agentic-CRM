//! D4-T2: speed to lead and stale-lead rebalancing.
//!
//! - **First touch.** With the setting [`FIRST_TOUCH_SETTING`] above zero,
//!   every new lead gets one M10 timer (kind [`TIMER_KIND`]) due that many
//!   minutes after it was created ([`schedule_timers`], every minute, for
//!   leads created in the last [`LOOKBACK_HOURS`] hours that have none). When
//!   it fires ([`fire`]), a lead that is still `new` and has no activity
//!   regarding it and no linked communication since it was created is
//!   escalated: its owner's managers (the position hierarchy, else the
//!   administrators, as for leavers, D7-T6) are notified, in one transaction.
//!   A lead touched, moved on or deleted meanwhile is left alone.
//! - **Rebalancing.** With the setting [`STALE_SETTING`] above zero, the
//!   daily [`rebalance`] takes open leads (`new` or `qualified`) given out by
//!   an assignment rule (D4-T1) that nobody has changed, and that have had no
//!   activity, for that many days, and gives each to someone else the same
//!   rule picks (the current owner left out of its pool), written through
//!   the record engine as the rule's owner with the reason `rebalanced`. The
//!   write moves the lead's `modified_at`, so a rebalanced lead waits the
//!   full period again. A rule that is disabled, no longer matches the lead
//!   or finds nobody else leaves it where it is.
//!
//! Both settings are zero by default: nothing is scheduled or moved until a
//! deployment sets them.

use attome_core::EngineState;
use attome_core::timer::{NewTimer, Timer};
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::lead_assignment::{self, RuleEntry};

/// The timer kind of a lead's first-touch deadline.
pub const TIMER_KIND: &str = "sales.first_touch";
/// The job that gives new leads their timer.
pub const SCHEDULE_JOB: &str = "lead_first_touch";
/// The daily rebalancing job.
pub const REBALANCE_JOB: &str = "lead_rebalance";
/// Minutes a new lead may wait for its first touch; 0 turns it off.
pub const FIRST_TOUCH_SETTING: &str = "sales.first_touch_minutes";
/// Days without activity after which a lead is rebalanced; 0 turns it off.
pub const STALE_SETTING: &str = "sales.stale_lead_days";
/// Leads older than this get no timer: a deployment that turns the setting
/// on is not flooded with escalations for its whole backlog.
pub const LOOKBACK_HOURS: i64 = 24;
/// Leads given a timer per run.
const SCHEDULE_BATCH: i64 = 200;
/// Leads looked at per rebalancing run.
const REBALANCE_BATCH: i64 = 500;

/// When a lead created at `created` must have been touched; `None` when the
/// check is off. Pure.
pub fn first_touch_due(created: DateTime<Utc>, minutes: i64) -> Option<DateTime<Utc>> {
    (minutes > 0).then(|| created + Duration::minutes(minutes))
}

/// The notification text of a missed first touch. Pure.
pub fn escalation_text(lead: &str, owner: &str, minutes: i64) -> String {
    format!(
        "The lead {lead}, owned by {owner}, has had no first touch {minutes} minutes after it came in."
    )
}

/// `pool` without `exclude`. Pure.
pub fn others(pool: &[Uuid], exclude: Option<Uuid>) -> Vec<Uuid> {
    pool.iter()
        .copied()
        .filter(|u| Some(*u) != exclude)
        .collect()
}

/// A whole-number setting, 0 when it is unset or not a number.
fn int_setting(state: &EngineState, key: &str) -> i64 {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(key)
        .map(|d| store.resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0)
}

fn has_attr(state: &EngineState, entity: &str, attr: &str) -> bool {
    state
        .entities
        .load()
        .get(entity)
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == attr))
}

fn uuid_of(row: &Value, key: &str) -> Option<Uuid> {
    row.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Gives each new lead without one its first-touch timer; returns how many
/// were scheduled.
pub async fn schedule_timers(state: &EngineState) -> Result<u64, AppError> {
    let minutes = int_setting(state, FIRST_TOUCH_SETTING);
    if minutes == 0 || !has_attr(state, "lead", "lead_status") {
        return Ok(0);
    }
    let db = &state.base.db;
    let leads: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT l.id, l.created_at FROM lead l \
          WHERE (l.is_active IS NULL OR l.is_active = true) AND l.lead_status = 'new' \
            AND l.created_at >= now() - make_interval(hours => $1::int) \
            AND NOT EXISTS (SELECT 1 FROM timer t \
                             WHERE t.kind = $2 AND t.target_entity = 'lead' AND t.target_id = l.id) \
          ORDER BY l.created_at, l.id LIMIT $3",
    )
    .bind(LOOKBACK_HOURS as i32)
    .bind(TIMER_KIND)
    .bind(SCHEDULE_BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if leads.is_empty() {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let mut scheduled = 0u64;
    for (id, created) in leads {
        let Some(due_at) = first_touch_due(created, minutes) else {
            continue;
        };
        attome_core::timer::schedule(
            &mut tx,
            &NewTimer {
                kind: TIMER_KIND.to_owned(),
                target_entity: Some("lead".to_owned()),
                target_id: Some(id),
                run_id: None,
                due_at,
                payload: json!({ "minutes": minutes }),
            },
        )
        .await?;
        scheduled += 1;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(scheduled)
}

/// Whether anyone touched the lead since `since`: an activity regarding it
/// or a communication linked to it.
async fn touched(state: &EngineState, lead: Uuid, since: DateTime<Utc>) -> Result<bool, AppError> {
    let db = &state.base.db;
    if has_attr(state, "activity", "regarding_entity")
        && has_attr(state, "activity", "regarding_id")
    {
        let any: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM activity \
              WHERE regarding_entity = 'lead' AND regarding_id::text = $1 AND created_at >= $2)",
        )
        .bind(lead.to_string())
        .bind(since)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if any {
            return Ok(true);
        }
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM communication_link \
          WHERE entity_name = 'lead' AND record_id = $1 AND created_at >= $2)",
    )
    .bind(lead)
    .bind(since)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Runs one fired first-touch timer (`EngineJob::TimerFire` for
/// [`TIMER_KIND`]): escalates the lead when it is still new and untouched.
pub async fn fire(state: &EngineState, timer: &Timer) -> Result<(), AppError> {
    let Some(id) = timer.target_id else {
        return Ok(());
    };
    let db = &state.base.db;
    // name, lead_status, owner_ref, created_by, created_at
    type LeadRow = (
        Option<String>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        DateTime<Utc>,
    );
    let lead: Option<LeadRow> = sqlx::query_as(
        "SELECT name, lead_status, owner_ref, created_by, created_at FROM lead \
              WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((name, status, owner, creator, created)) = lead else {
        return Ok(());
    };
    if status.as_deref() != Some("new") || touched(state, id, created).await? {
        return Ok(());
    }
    let Some(owner) = owner.or(creator) else {
        return Ok(());
    };
    let owner_name: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(user_name, ''), email) FROM user_account WHERE id = $1",
    )
    .bind(owner)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let minutes = timer.payload["minutes"].as_i64().unwrap_or(0);
    let lead_name = name.unwrap_or_else(|| "(no name)".to_owned());
    let body = escalation_text(
        &lead_name,
        owner_name.as_deref().unwrap_or("its owner"),
        minutes,
    );
    let recipients = attome_sales::leavers::managers(db, owner).await?;
    if recipients.is_empty() {
        tracing::warn!(lead = %id, "speed to lead: a missed first touch has nobody to escalate to");
        return Ok(());
    }
    let mut tx = attome_db::tx::begin(db).await?;
    for recipient in recipients {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(recipient),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(format!("No first touch yet: {lead_name}")),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(format!("/xrm/entity/lead/form?id={id}")),
            variables: std::collections::HashMap::new(),
            priority: "high".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch_in_tx(
            &mut tx,
            &state.base.config.notification,
            req,
            Some("sales.first_touch_missed"),
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(lead = %id, %owner, "speed to lead: missed first touch escalated");
    Ok(())
}

/// Gives each stale lead to someone else its rule picks; returns how many
/// moved.
pub async fn rebalance(state: &EngineState) -> Result<usize, AppError> {
    let days = int_setting(state, STALE_SETTING);
    if days == 0
        || !has_attr(state, "lead", "assignment_rule_ref")
        || !has_attr(state, "lead", "lead_status")
        || state.entities.load().get("lead_assignment_rule").is_none()
    {
        return Ok(0);
    }
    let db = &state.base.db;
    // The stale-lead query, with or without the recent-activity filter, as
    // one static string each (Z2-T11: nothing interpolated).
    macro_rules! stale_leads {
        ($no_activity:literal) => {
            concat!(
                "SELECT to_jsonb(l) FROM lead l \
                  WHERE (l.is_active IS NULL OR l.is_active = true) \
                    AND l.lead_status IN ('new', 'qualified') AND l.assignment_rule_ref IS NOT NULL \
                    AND COALESCE(l.modified_at, l.created_at) < now() - make_interval(days => $1::int) ",
                $no_activity,
                " ORDER BY COALESCE(l.modified_at, l.created_at), l.id LIMIT $2"
            )
        };
    }
    let sql = if has_attr(state, "activity", "regarding_entity")
        && has_attr(state, "activity", "regarding_id")
    {
        stale_leads!(
            "AND NOT EXISTS (SELECT 1 FROM activity a WHERE a.regarding_entity = 'lead' \
              AND a.regarding_id::text = l.id::text \
              AND a.created_at >= now() - make_interval(days => $1::int))"
        )
    } else {
        stale_leads!("")
    };
    let leads: Vec<Value> = sqlx::query_scalar(sql)
    .bind(days as i32)
    .bind(REBALANCE_BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut moved = 0;
    for lead in leads {
        let (Some(id), Some(rule_id)) =
            (uuid_of(&lead, "id"), uuid_of(&lead, "assignment_rule_ref"))
        else {
            continue;
        };
        let rule: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM lead_assignment_rule r WHERE r.id = $1 \
               AND (r.is_active IS NULL OR r.is_active = true) AND COALESCE(r.is_enabled, true)",
        )
        .bind(rule_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let Some(rule) = rule.as_ref().and_then(RuleEntry::from_row) else {
            continue;
        };
        if !rule.matches(&lead) {
            continue;
        }
        let current = uuid_of(&lead, "owner_ref").or_else(|| uuid_of(&lead, "created_by"));
        let Some(owner) = lead_assignment::pick_other(state, &rule, &lead, current).await? else {
            continue;
        };
        let Some(acting) = rule.author else {
            continue;
        };
        let version = lead.get("row_version").and_then(Value::as_i64).unwrap_or(0);
        let ctx = state.base.security.resolve_strict(acting).await?;
        match attome_records::entity_crud::update_record_for(
            state,
            &ctx,
            acting,
            "lead",
            id,
            version,
            json!({ "owner_ref": owner.to_string(), "assignment_reason": "rebalanced" }),
        )
        .await
        {
            Ok(_) => {
                moved += 1;
                tracing::info!(lead = %id, %owner, "stale lead rebalanced");
            }
            Err(
                error @ (AppError::Forbidden
                | AppError::AttributeNotWritable(_)
                | AppError::Validation(_)
                | AppError::Conflict(_)
                | AppError::VersionConflict
                | AppError::VersionConflictAt { .. }),
            ) => {
                tracing::warn!(lead = %id, %error, "stale lead not rebalanced");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_to_lead_due_is_minutes_after_creation() {
        let created = DateTime::from_timestamp(1_761_566_400, 0).unwrap();
        assert_eq!(
            first_touch_due(created, 15),
            Some(created + Duration::minutes(15))
        );
        assert_eq!(first_touch_due(created, 0), None, "zero turns it off");
        assert_eq!(first_touch_due(created, -5), None);
    }

    #[test]
    fn speed_to_lead_escalation_names_lead_owner_and_wait() {
        let text = escalation_text("Acme inquiry", "Sara", 15);
        assert!(text.contains("Acme inquiry"));
        assert!(text.contains("Sara"));
        assert!(text.contains("15 minutes"));
    }

    #[test]
    fn speed_to_lead_rebalance_leaves_the_current_owner_out() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_eq!(others(&[a, b], Some(a)), vec![b]);
        assert_eq!(others(&[a, b], None), vec![a, b]);
        assert!(others(&[a], Some(a)).is_empty());
    }
}
