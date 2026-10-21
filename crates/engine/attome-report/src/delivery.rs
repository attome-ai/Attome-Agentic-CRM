//! P3-T1: scheduled reports delivered to each recipient with their own
//! data.
//!
//! A `report_schedule`'s `recipients` (user ids or user email addresses,
//! separated by commas, semicolons or spaces) each get **their own run**:
//! [`crate::scheduler::fire`] creates one `report_run` per recipient with
//! `requested_by` = that recipient, so the run's query executes under the
//! recipient's own privileges, record rules and field security, exactly as
//! a manual run of theirs would (`crate::run`'s security model). A schedule
//! with no recipients runs once as its `run_as`, as before.
//!
//! When a scheduled run completes, [`deliver`] tells its recipient — in the
//! app (`delivery = in_app`) or also by email (`email_link`) — with a link
//! to the run, unless the run is empty and the schedule says
//! `skip_if_empty`. When a scheduled run fails, [`alert_owner`] tells the
//! schedule's owner which recipient's run failed and why. Both are best
//! effort after the run's own transaction: a lost notice is logged and the
//! run stays downloadable.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// Most recipients one schedule takes.
pub const MAX_RECIPIENTS: usize = 200;

/// A recipient as written on a schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    User(Uuid),
    Email(String),
}

/// Parses a schedule's `recipients`: ids and addresses separated by
/// commas, semicolons or whitespace, duplicates dropped, at most
/// [`MAX_RECIPIENTS`]; anything else is ignored. Pure.
pub fn parse_recipients(raw: Option<&str>) -> Vec<Recipient> {
    let mut out = Vec::new();
    for part in raw
        .unwrap_or_default()
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let r = match Uuid::parse_str(part) {
            Ok(id) => Recipient::User(id),
            Err(_) if part.contains('@') => Recipient::Email(part.to_lowercase()),
            Err(_) => continue,
        };
        if !out.contains(&r) {
            out.push(r);
        }
        if out.len() == MAX_RECIPIENTS {
            break;
        }
    }
    out
}

/// Whether a completed run is delivered. Pure.
pub fn should_deliver(row_count: i64, skip_if_empty: bool) -> bool {
    !(skip_if_empty && row_count == 0)
}

/// The active users a schedule's recipients name.
pub async fn resolve_recipients(
    db: &attome_db::DbPool,
    raw: Option<&str>,
) -> Result<Vec<Uuid>, AppError> {
    let parsed = parse_recipients(raw);
    if parsed.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = parsed
        .iter()
        .filter_map(|r| match r {
            Recipient::User(id) => Some(*id),
            Recipient::Email(_) => None,
        })
        .collect();
    let emails: Vec<String> = parsed
        .iter()
        .filter_map(|r| match r {
            Recipient::Email(e) => Some(e.clone()),
            Recipient::User(_) => None,
        })
        .collect();
    let mut users: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_account \
          WHERE (id = ANY($1) OR lower(email) = ANY($2)) \
            AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(&ids)
    .bind(&emails)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    users.dedup();
    Ok(users)
}

/// `(source, schedule, requested_by, row_count, report name, delivery,
/// skip_if_empty, schedule owner)`.
type RunRow = (
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<Uuid>,
);

async fn run_row(db: &attome_db::DbPool, run_id: Uuid) -> Result<Option<RunRow>, AppError> {
    sqlx::query_as(
        "SELECT r.source, r.schedule_ref, r.requested_by, r.row_count, a.name, \
                s.delivery::text, s.skip_if_empty, COALESCE(s.owner_ref, s.created_by) \
           FROM report_run r \
           LEFT JOIN attome_report a ON a.id = r.report_ref \
           LEFT JOIN report_schedule s ON s.id = r.schedule_ref \
          WHERE r.id = $1",
    )
    .bind(run_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn notify(
    state: &EngineState,
    user: Uuid,
    subject: String,
    body: String,
    route: String,
    email: bool,
) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: Some(if email {
            vec!["in_app".to_owned(), "email".to_owned()]
        } else {
            vec!["in_app".to_owned()]
        }),
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: Some(route),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        tracing::warn!(%user, %error, "report delivery: notice not sent");
    }
}

/// Tells a completed scheduled run's recipient that their report is ready.
pub async fn deliver(state: &EngineState, run_id: Uuid) {
    let row = match run_row(&state.base.db, run_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%run_id, %error, "report delivery: run not read");
            return;
        }
    };
    let (source, schedule, recipient, rows, name, delivery, skip, _) = row;
    if source.as_deref() != Some("scheduled") || schedule.is_none() {
        return;
    }
    let (Some(recipient), rows) = (recipient, rows.unwrap_or(0)) else {
        return;
    };
    if !should_deliver(rows, skip.unwrap_or(false)) {
        return;
    }
    let name = name.unwrap_or_else(|| "Your report".to_owned());
    notify(
        state,
        recipient,
        format!("{name} is ready"),
        format!("{name} ran on its schedule with {rows} row(s), under your own access. Open it to download."),
        format!("/reports/runs/{run_id}"),
        delivery.as_deref() == Some("email_link"),
    )
    .await;
}

/// Tells a scheduled run's schedule owner that the run failed.
pub async fn alert_owner(state: &EngineState, run_id: Uuid, message: &str) {
    let Ok(Some((source, schedule, recipient, _, name, _, _, owner))) =
        run_row(&state.base.db, run_id).await
    else {
        return;
    };
    if source.as_deref() != Some("scheduled") || schedule.is_none() {
        return;
    }
    let Some(owner) = owner else {
        return;
    };
    let name = name.unwrap_or_else(|| "A scheduled report".to_owned());
    let who = recipient.map_or_else(String::new, |r| format!(" for recipient {r}"));
    notify(
        state,
        owner,
        format!("{name} failed"),
        format!("The scheduled run{who} failed: {message}"),
        format!("/reports/runs/{run_id}"),
        false,
    )
    .await;
}

#[cfg(test)]
mod delivery_tests {
    use super::*;

    #[test]
    fn recipients_are_ids_or_addresses_once_each() {
        let id = Uuid::from_u128(7);
        let parsed = parse_recipients(Some(&format!(
            "{id}, Sara@Example.com; {id}  bad sara@example.com"
        )));
        assert_eq!(
            parsed,
            vec![
                Recipient::User(id),
                Recipient::Email("sara@example.com".into())
            ]
        );
        assert!(parse_recipients(None).is_empty());
        assert!(parse_recipients(Some(" , ;")).is_empty());
    }

    #[test]
    fn recipients_are_capped() {
        let many: Vec<String> = (0..300).map(|n| Uuid::from_u128(n).to_string()).collect();
        assert_eq!(
            parse_recipients(Some(&many.join(","))).len(),
            MAX_RECIPIENTS
        );
    }

    #[test]
    fn an_empty_run_is_skipped_only_when_asked() {
        assert!(should_deliver(0, false));
        assert!(!should_deliver(0, true));
        assert!(should_deliver(3, true));
    }
}
