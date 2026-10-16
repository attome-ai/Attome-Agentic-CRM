//! Contract key dates (roadmap W1-T4): the nightly job that keeps a
//! contract's notice deadline current, opens one "renew, renegotiate or
//! terminate" task per deadline when it comes within the lead time, reminds
//! obligation owners before a due date, escalates overdue obligations, and
//! rolls a completed recurring obligation forward.
//!
//! Every step is safe to run twice in a night:
//!
//! - the renewal task is one per contract and deadline (an existing task
//!   with that due date, open or not, means it was created);
//! - a reminder or escalation claims its obligation by setting
//!   `last_reminded_on` / `escalated_on` before it notifies, so a second run
//!   finds nothing to claim;
//! - a recurring obligation hands its `recurrence_rule` to the next
//!   occurrence it creates, in one transaction, so it is rolled once.
//!
//! The work goes in batches of [`BATCH`] in id order, each in its own short
//! transaction. The contract-management pack owns the tables; a deployment
//! without it has no `contract` table and the job does nothing.
//!
//! The platform has no manager link on users, so an overdue obligation
//! escalates to the contract's owner (and its own owner when different).

use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDate;
use uuid::Uuid;

/// Rows per batch.
pub const BATCH: i64 = 500;

/// The renewal task's subject.
pub const RENEWAL_TASK_SUBJECT: &str = "Renew, renegotiate or terminate";

/// When to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDateSettings {
    /// Days before the notice deadline the renewal task opens
    /// (`contract.renewal_lead_days`).
    pub renewal_lead_days: i64,
    /// Days before an obligation's due date its owner is reminded
    /// (`contract.obligation_reminder_days`).
    pub obligation_reminder_days: i64,
}

impl Default for KeyDateSettings {
    fn default() -> Self {
        Self {
            renewal_lead_days: 30,
            obligation_reminder_days: 7,
        }
    }
}

/// The last day notice can be given: the end date less the notice period
/// (none, or a negative one, is the end date itself).
pub fn notice_deadline(end_date: NaiveDate, notice_period_days: Option<i64>) -> NaiveDate {
    let days = notice_period_days.unwrap_or(0).max(0);
    end_date
        .checked_sub_signed(chrono::Duration::days(days))
        .unwrap_or(end_date)
}

/// Whether the renewal task is due on `today`.
pub fn renewal_due(deadline: NaiveDate, lead_days: i64, today: NaiveDate) -> bool {
    deadline
        .checked_sub_signed(chrono::Duration::days(lead_days.max(0)))
        .is_some_and(|opens| opens <= today)
}

// The recurrence rules live in the calendar crate so obligations, tasks
// and anything else that repeats read them the same way.
pub use attome_calendar::recurrence::{Recurrence, next_occurrence, parse_recurrence};

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyDateRun {
    pub deadlines_written: u64,
    pub renewal_tasks: u64,
    pub reminders: u64,
    pub escalations: u64,
    pub rolled_forward: u64,
    /// Approved amendments that took effect (W1-T11).
    pub amendments_applied: u64,
}

/// Runs every step for `today`.
pub async fn run(
    db: &DbPool,
    notification: &attome_config::NotificationSection,
    settings: KeyDateSettings,
    today: NaiveDate,
) -> Result<KeyDateRun, AppError> {
    let mut out = KeyDateRun::default();
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('contract') IS NOT NULL AND to_regclass('obligation') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(out);
    }
    // Today's amendments first, so deadlines follow the terms in force.
    apply_amendments(db, today, &mut out).await?;
    contracts(db, settings, today, &mut out).await?;
    remind(db, notification, settings, today, &mut out).await?;
    escalate(db, notification, today, &mut out).await?;
    roll_forward(db, &mut out).await?;
    Ok(out)
}

type ContractRow = (
    Uuid,
    Option<String>,
    NaiveDate,
    Option<f64>,
    Option<NaiveDate>,
    Option<Uuid>,
);

async fn contracts(
    db: &DbPool,
    settings: KeyDateSettings,
    today: NaiveDate,
    out: &mut KeyDateRun,
) -> Result<(), AppError> {
    let mut after = Uuid::nil();
    loop {
        let rows: Vec<ContractRow> = sqlx::query_as(
            "SELECT id, title, end_date::date, notice_period_days::float8, \
                    notice_deadline::date, owner_ref \
             FROM contract \
             WHERE (is_active IS NULL OR is_active = true) \
               AND status IN ('approved', 'active') AND end_date IS NOT NULL AND id > $1 \
             ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else { break };
        after = last.0;
        let full = rows.len() as i64 == BATCH;
        for (id, title, end_date, notice_days, stored, owner) in rows {
            let deadline = notice_deadline(end_date, notice_days.map(|d| d as i64));
            if stored != Some(deadline) {
                sqlx::query(
                    "UPDATE contract SET notice_deadline = $2, modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(id)
                .bind(deadline)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
                out.deadlines_written += 1;
            }
            if renewal_due(deadline, settings.renewal_lead_days, today)
                && deadline >= today
                && open_renewal_task(db, id, deadline, title.as_deref(), owner).await?
            {
                out.renewal_tasks += 1;
            }
        }
        if !full {
            break;
        }
    }
    Ok(())
}

/// Creates the renewal task for one contract and deadline unless it exists;
/// whether it created one.
async fn open_renewal_task(
    db: &DbPool,
    contract: Uuid,
    deadline: NaiveDate,
    title: Option<&str>,
    owner: Option<Uuid>,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-contract/renewal-task:{contract}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(false);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM activity \
         WHERE entity_name = 'contract' AND record_id = $1 AND activity_type = 'task' \
           AND subject = $2 AND due_at::date = $3)",
    )
    .bind(contract.to_string())
    .bind(RENEWAL_TASK_SUBJECT)
    .bind(deadline)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    let description = format!(
        "Notice for {} must be given by {deadline}. Decide whether to renew, renegotiate or \
         terminate.",
        title.unwrap_or("this contract")
    );
    sqlx::query(
        "INSERT INTO activity \
           (subject, activity_type, status, priority, entity_name, record_id, due_at, \
            description, owner_ref) \
         VALUES ($1, 'task', 'open', 'high', 'contract', $2, $3, $4, $5)",
    )
    .bind(RENEWAL_TASK_SUBJECT)
    .bind(contract.to_string())
    .bind(deadline)
    .bind(description)
    .bind(owner)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(true)
}

type ClaimedObligation = (Uuid, Option<String>, NaiveDate, Option<Uuid>, Option<Uuid>);

async fn remind(
    db: &DbPool,
    notification: &attome_config::NotificationSection,
    settings: KeyDateSettings,
    today: NaiveDate,
    out: &mut KeyDateRun,
) -> Result<(), AppError> {
    let until = today
        .checked_add_signed(chrono::Duration::days(
            settings.obligation_reminder_days.max(0),
        ))
        .unwrap_or(today);
    loop {
        // Claimed before anyone is notified: a second run finds nothing.
        let claimed: Vec<ClaimedObligation> = sqlx::query_as(
            "WITH due AS ( \
               SELECT id FROM obligation \
               WHERE (is_active IS NULL OR is_active = true) \
                 AND COALESCE(is_complete, false) = false AND last_reminded_on IS NULL \
                 AND due_date::date BETWEEN $1 AND $2 \
               ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED) \
             UPDATE obligation o SET last_reminded_on = $1 FROM due WHERE o.id = due.id \
             RETURNING o.id, o.title, o.due_date::date, o.owner_ref, NULL::uuid",
        )
        .bind(today)
        .bind(until)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let n = claimed.len() as i64;
        for (id, title, due, owner, _) in claimed {
            let Some(owner) = owner else { continue };
            let title = title.unwrap_or_else(|| "An obligation".to_owned());
            notify(
                db,
                notification,
                owner,
                format!("{title} is due on {due}"),
                format!("The contract obligation {title} is due on {due}."),
                id,
                "normal",
            )
            .await;
            out.reminders += 1;
        }
        if n < BATCH {
            break;
        }
    }
    Ok(())
}

async fn escalate(
    db: &DbPool,
    notification: &attome_config::NotificationSection,
    today: NaiveDate,
    out: &mut KeyDateRun,
) -> Result<(), AppError> {
    loop {
        let claimed: Vec<ClaimedObligation> = sqlx::query_as(
            "WITH overdue AS ( \
               SELECT id FROM obligation \
               WHERE (is_active IS NULL OR is_active = true) \
                 AND COALESCE(is_complete, false) = false AND escalated_on IS NULL \
                 AND due_date::date < $1 \
               ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED), \
             claimed AS ( \
               UPDATE obligation o SET escalated_on = $1 FROM overdue WHERE o.id = overdue.id \
               RETURNING o.id, o.title, o.due_date, o.owner_ref, o.contract_ref) \
             SELECT c.id, c.title, c.due_date::date, c.owner_ref, k.owner_ref \
             FROM claimed c LEFT JOIN contract k ON k.id = c.contract_ref",
        )
        .bind(today)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let n = claimed.len() as i64;
        for (id, title, due, owner, contract_owner) in claimed {
            let title = title.unwrap_or_else(|| "An obligation".to_owned());
            let mut recipients: Vec<Uuid> = contract_owner.into_iter().chain(owner).collect();
            recipients.dedup();
            for user in recipients {
                notify(
                    db,
                    notification,
                    user,
                    format!("Overdue: {title}"),
                    format!(
                        "The contract obligation {title} was due on {due} and is not complete."
                    ),
                    id,
                    "high",
                )
                .await;
            }
            out.escalations += 1;
        }
        if n < BATCH {
            break;
        }
    }
    Ok(())
}

type RecurringRow = (Uuid, NaiveDate, String);

async fn roll_forward(db: &DbPool, out: &mut KeyDateRun) -> Result<(), AppError> {
    let mut after = Uuid::nil();
    loop {
        let rows: Vec<RecurringRow> = sqlx::query_as(
            "SELECT id, due_date::date, recurrence_rule FROM obligation \
             WHERE (is_active IS NULL OR is_active = true) AND is_complete = true \
               AND recurrence_rule IS NOT NULL AND recurrence_rule <> '' \
               AND due_date IS NOT NULL AND id > $1 \
             ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else { break };
        after = last.0;
        let full = rows.len() as i64 == BATCH;
        for (id, due, rule) in rows {
            let Some(next) = parse_recurrence(&rule).and_then(|r| next_occurrence(r, due)) else {
                tracing::warn!(obligation = %id, rule, "contract key dates: unreadable recurrence rule");
                continue;
            };
            let mut tx = attome_db::tx::begin(db).await?;
            // The rule moves to the new occurrence; only the row still
            // holding it is rolled, so a second run does nothing.
            let moved = sqlx::query(
                "UPDATE obligation SET recurrence_rule = NULL, modified_at = now(), \
                 row_version = row_version + 1 \
                 WHERE id = $1 AND recurrence_rule = $2",
            )
            .bind(id)
            .bind(&rule)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if moved.rows_affected() != 1 {
                continue;
            }
            sqlx::query(
                "INSERT INTO obligation \
                   (title, contract_ref, owner_ref, owner_type, organization_ref, owed_by, \
                    recurrence_rule, due_date, is_complete) \
                 SELECT title, contract_ref, owner_ref, owner_type, organization_ref, owed_by, \
                        $2, $3, false \
                 FROM obligation WHERE id = $1",
            )
            .bind(id)
            .bind(&rule)
            .bind(next)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            tx.commit().await.map_err(AppError::internal)?;
            out.rolled_forward += 1;
        }
        if !full {
            break;
        }
    }
    Ok(())
}

type DueAmendment = (Uuid, Uuid, NaiveDate, Option<String>);

/// W1-T11: approved amendments whose effective date has come are folded
/// over their contract's current terms (in effective-date order, then
/// creation order) and marked `effective`, one contract per transaction.
/// The amendment rows are the history; only `current_terms` and, when an
/// amendment changes it, `end_date` are rewritten. The status change makes
/// a second run apply nothing.
async fn apply_amendments(
    db: &DbPool,
    today: NaiveDate,
    out: &mut KeyDateRun,
) -> Result<(), AppError> {
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('amendment') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(());
    }
    loop {
        let due: Vec<DueAmendment> = sqlx::query_as(
            "SELECT id, contract_ref, effective_date::date, changed_terms FROM amendment \
             WHERE (is_active IS NULL OR is_active = true) AND status = 'approved' \
               AND contract_ref IS NOT NULL AND effective_date::date <= $1 \
             ORDER BY contract_ref, effective_date, created_at, id LIMIT $2",
        )
        .bind(today)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if due.is_empty() {
            break;
        }
        let full = due.len() as i64 == BATCH;
        let mut contracts: Vec<Uuid> = due.iter().map(|d| d.1).collect();
        contracts.dedup();
        for contract in contracts {
            let mine: Vec<&DueAmendment> = due.iter().filter(|d| d.1 == contract).collect();
            out.amendments_applied += apply_to_contract(db, contract, &mine).await?;
        }
        if !full {
            break;
        }
    }
    Ok(())
}

async fn apply_to_contract(
    db: &DbPool,
    contract: Uuid,
    due: &[&DueAmendment],
) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(Option<String>, Option<NaiveDate>)> = sqlx::query_as(
        "SELECT current_terms, end_date::date FROM contract WHERE id = $1 FOR UPDATE",
    )
    .bind(contract)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((terms_text, end_date)) = row else {
        return Ok(0);
    };
    let base: serde_json::Map<String, serde_json::Value> = terms_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok())
        .unwrap_or_default();
    let amendments: Vec<crate::amendment::Amendment> = due
        .iter()
        .enumerate()
        .map(
            |(i, (_, _, effective_date, changed))| crate::amendment::Amendment {
                effective_date: *effective_date,
                sequence: u32::try_from(i).unwrap_or(u32::MAX),
                changed_terms: changed
                    .as_deref()
                    .and_then(|t| serde_json::from_str(t).ok())
                    .unwrap_or_default(),
            },
        )
        .collect();
    let today = amendments
        .iter()
        .map(|a| a.effective_date)
        .max()
        .unwrap_or(NaiveDate::MIN);
    let terms = crate::amendment::current_terms(&base, &amendments, today);
    let new_end = crate::amendment::current_end_date(&terms, end_date);
    let ids: Vec<Uuid> = due.iter().map(|d| d.0).collect();
    let marked = sqlx::query(
        "UPDATE amendment SET status = 'effective', modified_at = now(), \
         row_version = row_version + 1 WHERE id = ANY($1) AND status = 'approved'",
    )
    .bind(&ids)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if marked == 0 {
        return Ok(0);
    }
    sqlx::query(
        "UPDATE contract SET current_terms = $2, end_date = $3, modified_at = now(), \
         row_version = row_version + 1 WHERE id = $1",
    )
    .bind(contract)
    .bind(serde_json::Value::Object(terms).to_string())
    .bind(new_end)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(marked)
}

/// Sends one in-app notification; a failure is logged, never fatal, since
/// the claim already stands.
async fn notify(
    db: &DbPool,
    notification: &attome_config::NotificationSection,
    user: Uuid,
    subject: String,
    body: String,
    obligation: Uuid,
    priority: &str,
) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: Some(format!("/xrm/entity/obligation/{obligation}")),
        variables: std::collections::HashMap::new(),
        priority: priority.to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(db, notification, req).await
    {
        tracing::warn!(%obligation, %user, %error, "contract key dates: notification failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap_or_default()
    }

    #[test]
    fn notice_deadline_subtracts_days() {
        assert_eq!(
            notice_deadline(day(2026, 12, 31), Some(90)),
            day(2026, 10, 2)
        );
        assert_eq!(notice_deadline(day(2026, 12, 31), None), day(2026, 12, 31));
        assert_eq!(
            notice_deadline(day(2026, 12, 31), Some(-5)),
            day(2026, 12, 31)
        );
        assert!(renewal_due(day(2026, 10, 31), 30, day(2026, 10, 1)));
        assert!(!renewal_due(day(2026, 10, 31), 30, day(2026, 9, 30)));
    }
}
