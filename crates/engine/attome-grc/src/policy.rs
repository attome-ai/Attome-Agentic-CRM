//! R9-T1: policy reviews, attestation campaigns and exceptions.
//!
//! The grc pack's `0001` adds a review date (`review_by`) and cadence
//! (`review_every_days`) to `grc_policy`, attestation campaigns
//! (`grc_attestation_campaign`: a policy, a role and a due date) and policy
//! exceptions (`grc_policy_exception`: requested, approved, rejected or
//! expired, with `expires_on`). The daily `grc_policy_sweep` job:
//!
//! - **reminds a policy's owner** once, [`REVIEW_LEAD_DAYS`] before its review
//!   date. The policy is claimed by writing the date into
//!   `review_reminded_on` before anyone is told, so a second run finds
//!   nothing and a moved review date is reminded again;
//! - **asks each holder of an open campaign's role** who has not acknowledged
//!   the policy's current version (`grc_policy_ack.policy_version`) to do so,
//!   once per campaign (claimed through `reminded_on`), and closes a campaign
//!   once its due date has passed;
//! - **expires approved exceptions** whose `expires_on` has passed.
//!
//! [`attestation_progress`] gives a campaign's acknowledged and missing
//! holders. Every write is a guarded engine update (row version bumped), and
//! a reminder that fails to send is logged, not retried: its claim stands.
//! A deployment without the grc pack does nothing.

use std::collections::BTreeSet;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDate;
use uuid::Uuid;

/// The registered daily job.
pub const JOB: &str = "grc_policy_sweep";
/// How many days before its review date a policy's owner is reminded.
pub const REVIEW_LEAD_DAYS: i64 = 14;
/// Rows claimed per batch.
const BATCH: i64 = 200;

/// What one sweep did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySweep {
    pub review_reminders: u64,
    pub attestation_requests: u64,
    pub campaigns_closed: u64,
    pub exceptions_expired: u64,
}

/// Whether a policy reviewed by `review_by`, last reminded for
/// `reminded_for`, is to be reminded `today`. Pure.
pub fn review_due(review_by: NaiveDate, reminded_for: Option<NaiveDate>, today: NaiveDate) -> bool {
    let from = review_by
        .checked_sub_signed(chrono::Duration::days(REVIEW_LEAD_DAYS))
        .unwrap_or(review_by);
    today >= from && reminded_for != Some(review_by)
}

/// The next review date after a review on `reviewed_on`, when the policy
/// has a cadence. Pure.
pub fn next_review(reviewed_on: NaiveDate, every_days: Option<f64>) -> Option<NaiveDate> {
    let days = every_days.filter(|d| d.is_finite() && *d >= 1.0)?.round() as i64;
    reviewed_on.checked_add_signed(chrono::Duration::days(days))
}

/// A campaign's holders split into those who acknowledged and those still
/// to. Pure.
pub fn attestation_progress(
    holders: &BTreeSet<Uuid>,
    acknowledged: &BTreeSet<Uuid>,
) -> (Vec<Uuid>, Vec<Uuid>) {
    let done = holders.intersection(acknowledged).copied().collect();
    let missing = holders.difference(acknowledged).copied().collect();
    (done, missing)
}

async fn installed(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('grc_attestation_campaign') IS NOT NULL \
            AND to_regclass('grc_policy_exception') IS NOT NULL \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = 'grc_policy' \
                           AND column_name = 'review_reminded_on')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

async fn notify(
    state: &EngineState,
    user: Uuid,
    subject: String,
    body: String,
    route: String,
) -> bool {
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
        route: Some(route),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    match attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(%user, %error, "grc policy reminder failed");
            false
        }
    }
}

/// `(policy, title, review_by, owner)`.
type ClaimedReview = (Uuid, Option<String>, NaiveDate, Option<Uuid>);

/// Reminds owners of policies whose review is near.
async fn remind_reviews(state: &EngineState, today: NaiveDate) -> Result<u64, AppError> {
    let until = today
        .checked_add_signed(chrono::Duration::days(REVIEW_LEAD_DAYS))
        .unwrap_or(today);
    let mut sent = 0;
    loop {
        let claimed: Vec<ClaimedReview> = sqlx::query_as(
            "WITH due AS ( \
               SELECT id FROM grc_policy \
                WHERE COALESCE(status::text, 'active') = 'active' \
                  AND (is_active IS NULL OR is_active = true) \
                  AND review_by::date <= $1 \
                  AND review_reminded_on::date IS DISTINCT FROM review_by::date \
                ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED) \
             UPDATE grc_policy p SET review_reminded_on = p.review_by::date, \
                    row_version = p.row_version + 1 \
               FROM due WHERE p.id = due.id \
             RETURNING p.id, p.title, p.review_by::date, COALESCE(p.owner_id, p.created_by)",
        )
        .bind(until)
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let n = claimed.len() as i64;
        for (id, title, review_by, owner) in claimed {
            let Some(owner) = owner else { continue };
            let title = title.unwrap_or_else(|| "A policy".to_owned());
            if notify(
                state,
                owner,
                format!("{title} is due for review on {review_by}"),
                format!("The policy {title} is due for review on {review_by}."),
                format!("/xrm/entity/grc_policy/{id}"),
            )
            .await
            {
                sent += 1;
            }
        }
        if n < BATCH {
            break;
        }
    }
    Ok(sent)
}

/// `(campaign, name, policy, policy title, policy version, role, due)`.
type ClaimedCampaign = (
    Uuid,
    String,
    Uuid,
    Option<String>,
    Option<String>,
    Uuid,
    NaiveDate,
);

/// The holders of `role`.
async fn holders(db: &DbPool, role: Uuid) -> Result<BTreeSet<Uuid>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT r.user_ref FROM user_account_mm_role r \
           JOIN user_account u ON u.id = r.user_ref \
          WHERE r.role_ref = $1 AND NOT r.is_deleted AND u.is_active",
    )
    .bind(role)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(ids.into_iter().collect())
}

/// Who has acknowledged `version` of `policy`.
async fn acknowledged(
    db: &DbPool,
    policy: Uuid,
    version: Option<&str>,
) -> Result<BTreeSet<Uuid>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM grc_policy_ack \
          WHERE policy_id = $1 AND (is_active IS NULL OR is_active = true) \
            AND ($2::text IS NULL OR policy_version = $2)",
    )
    .bind(policy)
    .bind(version)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(ids.into_iter().collect())
}

/// The acknowledged and missing holders of a campaign.
pub async fn campaign_progress(
    db: &DbPool,
    campaign: Uuid,
) -> Result<(Vec<Uuid>, Vec<Uuid>), AppError> {
    let row: Option<(Uuid, Option<String>, Uuid)> = sqlx::query_as(
        "SELECT c.policy_ref, p.version, c.role_ref FROM grc_attestation_campaign c \
           JOIN grc_policy p ON p.id = c.policy_ref WHERE c.id = $1",
    )
    .bind(campaign)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (policy, version, role) = row.ok_or(AppError::NotFound)?;
    let members = holders(db, role).await?;
    let acked = acknowledged(db, policy, version.as_deref()).await?;
    Ok(attestation_progress(&members, &acked))
}

/// Asks open campaigns' missing holders to acknowledge, once per campaign.
async fn request_attestations(state: &EngineState, today: NaiveDate) -> Result<u64, AppError> {
    let db = &state.base.db;
    let claimed: Vec<ClaimedCampaign> = sqlx::query_as(
        "WITH due AS ( \
           SELECT id FROM grc_attestation_campaign \
            WHERE COALESCE(status::text, 'open') = 'open' \
              AND (is_active IS NULL OR is_active = true) \
              AND reminded_on IS NULL AND due_on::date >= $1 \
            ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED) \
         UPDATE grc_attestation_campaign c SET reminded_on = $1, \
                row_version = c.row_version + 1 \
           FROM due, grc_policy p \
          WHERE c.id = due.id AND p.id = c.policy_ref \
         RETURNING c.id, c.name, c.policy_ref, p.title, p.version, c.role_ref, c.due_on::date",
    )
    .bind(today)
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut sent = 0;
    for (campaign, name, policy, title, version, role, due) in claimed {
        let members = holders(db, role).await?;
        let acked = acknowledged(db, policy, version.as_deref()).await?;
        let (_, missing) = attestation_progress(&members, &acked);
        let title = title.unwrap_or_else(|| "a policy".to_owned());
        for user in missing {
            if notify(
                state,
                user,
                format!("Please acknowledge {title} by {due}"),
                format!(
                    "The attestation campaign {name} asks you to read and acknowledge the \
                     policy {title} by {due}."
                ),
                format!("/xrm/entity/grc_policy/{policy}"),
            )
            .await
            {
                sent += 1;
            }
        }
        tracing::debug!(%campaign, "attestation requests sent");
    }
    Ok(sent)
}

/// Closes open campaigns whose due date has passed.
async fn close_campaigns(db: &DbPool, today: NaiveDate) -> Result<u64, AppError> {
    sqlx::query(
        "UPDATE grc_attestation_campaign SET status = 'closed', row_version = row_version + 1 \
          WHERE COALESCE(status::text, 'open') = 'open' AND due_on::date < $1",
    )
    .bind(today)
    .execute(db)
    .await
    .map_err(AppError::internal)
    .map(|r| r.rows_affected())
}

/// Expires approved exceptions whose end has passed.
async fn expire_exceptions(db: &DbPool, today: NaiveDate) -> Result<u64, AppError> {
    sqlx::query(
        "UPDATE grc_policy_exception SET status = 'expired', row_version = row_version + 1 \
          WHERE status::text = 'approved' AND expires_on::date < $1",
    )
    .bind(today)
    .execute(db)
    .await
    .map_err(AppError::internal)
    .map(|r| r.rows_affected())
}

/// One day's sweep.
pub async fn sweep(state: &EngineState, today: NaiveDate) -> Result<PolicySweep, AppError> {
    let db = &state.base.db;
    if !installed(db).await? {
        return Ok(PolicySweep::default());
    }
    Ok(PolicySweep {
        review_reminders: remind_reviews(state, today).await?,
        attestation_requests: request_attestations(state, today).await?,
        campaigns_closed: close_campaigns(db, today).await?,
        exceptions_expired: expire_exceptions(db, today).await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, day).unwrap()
    }

    #[test]
    fn policy_review_is_reminded_once_inside_the_lead() {
        assert!(!review_due(d(11, 30), None, d(11, 1)), "too early");
        assert!(review_due(d(11, 30), None, d(11, 16)));
        assert!(
            review_due(d(11, 30), None, d(12, 5)),
            "overdue is still reminded"
        );
        assert!(!review_due(d(11, 30), Some(d(11, 30)), d(11, 20)), "once");
        assert!(
            review_due(d(12, 30), Some(d(11, 30)), d(12, 20)),
            "a moved date again"
        );
    }

    #[test]
    fn policy_next_review_follows_the_cadence() {
        assert_eq!(next_review(d(1, 1), Some(90.0)), Some(d(4, 1)));
        assert_eq!(next_review(d(1, 1), None), None);
        assert_eq!(next_review(d(1, 1), Some(0.0)), None);
    }

    #[test]
    fn policy_attestation_splits_done_and_missing() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        let holders: BTreeSet<Uuid> = [a, b, c].into();
        let acked: BTreeSet<Uuid> = [b, Uuid::from_u128(9)].into();
        assert_eq!(
            attestation_progress(&holders, &acked),
            (vec![b], vec![a, c])
        );
    }
}
