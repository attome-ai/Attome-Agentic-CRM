//! G8-T1: escalation rule sets, compiled into M10 timers.
//!
//! A `service_escalation_rule` names a condition on the ticket (an
//! attome-rules expression over its fields, e.g. `priority == "critical"`)
//! and steps, each a delay in business time and an action:
//!
//! ```json
//! [{ "after_minutes": 30,  "action": "notify" },
//!  { "after_minutes": 120, "action": "raise_priority" },
//!  { "after_minutes": 240, "action": "reassign", "to": "0190…" }]
//! ```
//!
//! When a ticket starts to match an enabled rule (seen by the ticket sweep
//! from the change feed), every step becomes one timer (`timer` kind
//! [`TIMER_KIND`]) due its delay after that moment, counted in the business
//! hours of the ticket's SLA policy (wall-clock time without one). When the
//! ticket stops matching, or is resolved or closed, its pending timers for
//! the rule are cancelled. A fired step re-checks the rule and the ticket,
//! acts, and records `escalation_level` and `escalated_at` on the ticket with
//! an internal note naming the rule.
//!
//! A condition that does not compile, names a field the ticket does not have
//! (or has empty), or evaluates to anything but a boolean, does not match:
//! a broken rule escalates nothing rather than everything.

use attome_config::NotificationSection;
use attome_core::timer::{NewTimer, Timer};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// The timer kind an escalation step is scheduled as.
pub const TIMER_KIND: &str = "service.escalation";
/// The entity escalation rules apply to.
pub const TICKET: &str = "service_ticket";
/// Most steps a rule has.
pub const MAX_STEPS: usize = 10;
/// Longest delay of a step: a year of minutes.
pub const MAX_DELAY_MINUTES: i64 = 525_600;

/// What a step does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepAction {
    /// Tell `to`, or the ticket's assignee.
    Notify,
    /// Give the ticket to `to`.
    Reassign,
    /// Raise the ticket's priority one level.
    RaisePriority,
}

impl StepAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::Reassign => "reassign",
            Self::RaisePriority => "raise_priority",
        }
    }
}

/// One step of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub after_minutes: i64,
    pub action: StepAction,
    #[serde(default)]
    pub to: Option<Uuid>,
}

/// A rule's steps, checked: 1 to [`MAX_STEPS`], delays rising from 1 minute
/// to a year, a person to reassign to. Pure.
pub fn parse_steps(raw: &str) -> Result<Vec<Step>, String> {
    let steps: Vec<Step> =
        serde_json::from_str(raw).map_err(|e| format!("steps are not valid: {e}"))?;
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err(format!("a rule has 1 to {MAX_STEPS} steps"));
    }
    let mut last = 0;
    for (i, step) in steps.iter().enumerate() {
        if !(1..=MAX_DELAY_MINUTES).contains(&step.after_minutes) || step.after_minutes <= last {
            return Err(format!(
                "step {}: after_minutes rises from 1 to {MAX_DELAY_MINUTES}",
                i + 1
            ));
        }
        if step.action == StepAction::Reassign && step.to.is_none() {
            return Err(format!("step {}: reassign names the person in `to`", i + 1));
        }
        last = step.after_minutes;
    }
    Ok(steps)
}

/// The next priority up; `critical` stays `critical`. Pure.
pub fn raised_priority(priority: &str) -> &'static str {
    match priority {
        "low" => "medium",
        "medium" => "high",
        _ => "critical",
    }
}

/// Whether the ticket (its fields as JSON) matches `condition`; no condition
/// matches every ticket. Fails closed to no match. Pure.
pub fn condition_holds(condition: Option<&str>, ticket: &Value) -> bool {
    let Some(condition) = condition.map(str::trim).filter(|c| !c.is_empty()) else {
        return true;
    };
    let (schema, ctx) = attome_audit::approval::schema_and_context_for_payload(ticket);
    match attome_rules::compile(condition, &schema).and_then(|c| c.eval(&ctx)) {
        Ok(attome_rules::Value::Bool(b)) => b,
        _ => false,
    }
}

/// When a step falls due from `anchor` without an SLA calendar. Pure.
pub fn wall_clock_due(anchor: DateTime<Utc>, after_minutes: i64) -> DateTime<Utc> {
    anchor + chrono::Duration::minutes(after_minutes)
}

/// One enabled rule.
#[derive(Debug, Clone, sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    name: String,
    condition: Option<String>,
    steps: Option<String>,
}

async fn enabled_rules(db: &DbPool) -> Result<Vec<RuleRow>, AppError> {
    let provisioned: bool =
        sqlx::query_scalar("SELECT to_regclass('service_escalation_rule') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !provisioned {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT id, name, condition, steps FROM service_escalation_rule \
          WHERE (is_active IS NULL OR is_active = true) AND is_enabled = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

async fn ticket_json(db: &DbPool, ticket_id: Uuid) -> Result<Option<Value>, AppError> {
    sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM service_ticket t \
          WHERE t.id = $1 AND (t.is_active IS NULL OR t.is_active = true)",
    )
    .bind(ticket_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

fn is_open(ticket: &Value) -> bool {
    !matches!(ticket["status"].as_str(), Some("resolved" | "closed"))
}

/// When a step falls due: its delay after `anchor` in the business hours of
/// the ticket's SLA policy, or wall-clock time without one (or when the
/// calendar cannot be resolved).
async fn step_due(
    db: &DbPool,
    ticket: &Value,
    anchor: DateTime<Utc>,
    after_minutes: i64,
) -> Result<DateTime<Utc>, AppError> {
    let policy_id = ticket["sla_policy_id"]
        .as_str()
        .and_then(|p| Uuid::parse_str(p).ok());
    if let Some(policy_id) = policy_id
        && let Some(policy) = crate::sla::policy_by_id(db, policy_id).await?
        && let Ok(due) = crate::sla::compute_due(db, &policy, anchor, after_minutes)
            .await?
            .outcome
    {
        return Ok(due);
    }
    Ok(wall_clock_due(anchor, after_minutes))
}

/// Brings one ticket's escalation timers in line with the enabled rules:
/// schedules the steps of a rule it newly matches, cancels the pending steps
/// of one it no longer matches, and all of them once it is resolved or
/// closed. Returns how many timers it scheduled.
pub async fn schedule_for_ticket(db: &DbPool, ticket_id: Uuid) -> Result<u64, AppError> {
    let rules = enabled_rules(db).await?;
    let ticket = ticket_json(db, ticket_id).await?;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let Some(ticket) = ticket.filter(is_open) else {
        sqlx::query(
            "UPDATE timer SET status = 'cancelled' \
              WHERE kind = $1 AND target_entity = $2 AND target_id = $3 AND status = 'pending'",
        )
        .bind(TIMER_KIND)
        .bind(TICKET)
        .bind(ticket_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        return Ok(0);
    };
    let now = Utc::now();
    let mut scheduled = 0u64;
    for rule in rules {
        let rule_key = rule.id.to_string();
        if !condition_holds(rule.condition.as_deref(), &ticket) {
            sqlx::query(
                "UPDATE timer SET status = 'cancelled' \
                  WHERE kind = $1 AND target_entity = $2 AND target_id = $3 \
                    AND status = 'pending' AND payload->>'rule_id' = $4",
            )
            .bind(TIMER_KIND)
            .bind(TICKET)
            .bind(ticket_id)
            .bind(&rule_key)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            continue;
        }
        // Already scheduled for this ticket (pending or done): a match is
        // escalated once until it stops matching.
        let scheduled_before: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM timer \
              WHERE kind = $1 AND target_entity = $2 AND target_id = $3 \
                AND payload->>'rule_id' = $4 AND status IN ('pending', 'fired', 'done'))",
        )
        .bind(TIMER_KIND)
        .bind(TICKET)
        .bind(ticket_id)
        .bind(&rule_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if scheduled_before {
            continue;
        }
        let steps = match parse_steps(rule.steps.as_deref().unwrap_or_default()) {
            Ok(steps) => steps,
            Err(reason) => {
                tracing::warn!(rule = %rule.name, %reason, "escalation rule skipped: its steps are not valid");
                continue;
            }
        };
        let mut dues = Vec::with_capacity(steps.len());
        for step in &steps {
            dues.push(step_due(db, &ticket, now, step.after_minutes).await?);
        }
        let mut tx = attome_db::tx::begin(db).await?;
        for (index, (step, due_at)) in steps.iter().zip(dues).enumerate() {
            attome_core::timer::schedule(
                &mut tx,
                &NewTimer {
                    kind: TIMER_KIND.to_owned(),
                    target_entity: Some(TICKET.to_owned()),
                    target_id: Some(ticket_id),
                    run_id: None,
                    due_at,
                    payload: json!({
                        "rule_id": rule_key,
                        "step": index,
                        "action": step.action.as_str(),
                    }),
                },
            )
            .await?;
            scheduled += 1;
        }
        tx.commit().await.map_err(AppError::internal)?;
    }
    Ok(scheduled)
}

/// Runs one fired escalation step (`EngineJob::TimerFire` for
/// [`TIMER_KIND`]): when its rule is still enabled and the ticket is open
/// and still matches, acts and records the escalation; otherwise does
/// nothing.
pub async fn fire(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    timer: &Timer,
) -> Result<(), AppError> {
    let Some(ticket_id) = timer.target_id else {
        return Ok(());
    };
    let rule_id = timer.payload["rule_id"]
        .as_str()
        .and_then(|r| Uuid::parse_str(r).ok());
    let index = timer.payload["step"].as_u64().unwrap_or(u64::MAX);
    let Some(rule) = enabled_rules(db)
        .await?
        .into_iter()
        .find(|r| Some(r.id) == rule_id)
    else {
        return Ok(());
    };
    let Ok(steps) = parse_steps(rule.steps.as_deref().unwrap_or_default()) else {
        return Ok(());
    };
    let Some(step) = usize::try_from(index).ok().and_then(|i| steps.get(i)) else {
        return Ok(());
    };
    let Some(ticket) = ticket_json(db, ticket_id).await?.filter(is_open) else {
        return Ok(());
    };
    if !condition_holds(rule.condition.as_deref(), &ticket) {
        return Ok(());
    }
    let level = i32::try_from(index + 1).unwrap_or(i32::MAX);
    let assignee = ticket["assignee_id"]
        .as_str()
        .and_then(|a| Uuid::parse_str(a).ok());

    let mut tx = attome_db::tx::begin(db).await?;
    match step.action {
        StepAction::Reassign => {
            sqlx::query("UPDATE service_ticket SET assignee_id = $2 WHERE id = $1")
                .bind(ticket_id)
                .bind(step.to)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        }
        StepAction::RaisePriority => {
            let raised = raised_priority(ticket["priority"].as_str().unwrap_or_default());
            sqlx::query("UPDATE service_ticket SET priority = $2 WHERE id = $1")
                .bind(ticket_id)
                .bind(raised)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        }
        StepAction::Notify => {}
    }
    sqlx::query(
        "UPDATE service_ticket \
            SET escalation_level = GREATEST(coalesce(escalation_level, 0), $2), \
                escalated_at = NOW() \
          WHERE id = $1",
    )
    .bind(ticket_id)
    .bind(level)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO note (id, entity_name, record_id, note_text, is_customer_visible) \
         VALUES ($1, 'service_ticket', $2, $3, false)",
    )
    .bind(Uuid::now_v7())
    .bind(ticket_id.to_string())
    .bind(format!(
        "Escalated by rule \"{}\", step {}: {}.",
        rule.name,
        index + 1,
        step.action.as_str().replace('_', " ")
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_named(
        &mut tx,
        TICKET,
        ticket_id,
        attome_core::change_feed::ChangeOperation::Update,
        "sla.escalated",
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    let recipients: Vec<Uuid> = match step.action {
        StepAction::Notify => step.to.or(assignee).into_iter().collect(),
        StepAction::Reassign => step.to.into_iter().collect(),
        StepAction::RaisePriority => assignee.into_iter().collect(),
    };
    if !recipients.is_empty() {
        let title = ticket["title"].as_str().unwrap_or("a ticket");
        crate::clock::notify_recipients(
            db,
            notification_cfg,
            &recipients,
            &format!("Escalation: {title}"),
            &format!(
                "Rule \"{}\" escalated this ticket (step {}: {}).",
                rule.name,
                index + 1,
                step.action.as_str().replace('_', " ")
            ),
            format!("/xrm/service_ticket/{ticket_id}"),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod escalation_rules {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn escalation_rules_steps_rise_and_name_whom_to_reassign() {
        let ok = parse_steps(
            r#"[{"after_minutes": 30, "action": "notify"},
                {"after_minutes": 120, "action": "raise_priority"},
                {"after_minutes": 240, "action": "reassign", "to": "01900000-0000-7000-8000-000000000001"}]"#,
        );
        assert_eq!(ok.map(|s| s.len()), Ok(3));
        assert!(parse_steps("[]").is_err());
        assert!(parse_steps(r#"[{"after_minutes": 0, "action": "notify"}]"#).is_err());
        assert!(
            parse_steps(
                r#"[{"after_minutes": 60, "action": "notify"}, {"after_minutes": 30, "action": "notify"}]"#
            )
            .is_err()
        );
        assert!(parse_steps(r#"[{"after_minutes": 60, "action": "reassign"}]"#).is_err());
        assert!(parse_steps(r#"[{"after_minutes": 60, "action": "page"}]"#).is_err());
    }

    #[test]
    fn escalation_rules_raise_priority_one_level() {
        assert_eq!(raised_priority("low"), "medium");
        assert_eq!(raised_priority("medium"), "high");
        assert_eq!(raised_priority("high"), "critical");
        assert_eq!(raised_priority("critical"), "critical");
    }

    #[test]
    fn escalation_rules_match_on_the_tickets_fields_and_fail_closed() {
        let ticket = json!({"priority": "critical", "major": true, "escalation_level": 0});
        assert!(condition_holds(None, &ticket));
        assert!(condition_holds(Some("  "), &ticket));
        assert!(condition_holds(Some("priority == \"critical\""), &ticket));
        assert!(!condition_holds(Some("priority == \"low\""), &ticket));
        // A field the ticket does not have, or a broken rule: no match.
        assert!(!condition_holds(Some("nonexistent == \"x\""), &ticket));
        assert!(!condition_holds(Some("priority =="), &ticket));
    }

    #[test]
    fn escalation_rules_fall_due_after_their_delay_on_a_fake_clock() {
        let anchor = Utc
            .with_ymd_and_hms(2026, 10, 19, 9, 0, 0)
            .single()
            .unwrap_or_default();
        assert_eq!(
            wall_clock_due(anchor, 90),
            Utc.with_ymd_and_hms(2026, 10, 19, 10, 30, 0)
                .single()
                .unwrap_or_default()
        );
    }
}
