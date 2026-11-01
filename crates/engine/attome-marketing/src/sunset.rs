//! E6-T9: the nightly sunset policy.
//!
//! While the deliverability policy's `sunset_enabled` is on, each night
//! ([`JOB`], [`run`]), for contacts and leads that carry the sunset
//! attributes ([`attome_core::engagement::tracks`]):
//!
//! 1. people with no marketing engagement for `sunset_months` (counted from
//!    `last_marketing_engagement_at`, or from when they were created when
//!    they never engaged), not yet invited back and not sunset, who consent
//!    to email for the policy's `reengagement_purpose`, get **one**
//!    re-engagement email: an E3 send of the policy's
//!    `reengagement_design_ref` (`email_campaign_send` with its recipients,
//!    which the `email_campaign` job sends, reading consent again and
//!    honouring unsubscribes and the weekly cap), and `reengagement_sent_at`
//!    is set in the same transaction as the send is queued;
//! 2. people invited back more than [`WAIT_DAYS`] days ago who have not
//!    engaged since are sunset: `marketing_sunset_at = now()`. E3 leaves a
//!    sunset person out of every campaign's audience.
//!
//! An open or click (D16 tracking and tracked campaign emails) or a form
//! submission brings a person back ([`attome_core::engagement::touch`]):
//! both dates are cleared and `last_marketing_engagement_at` set.
//!
//! One run at a time: the run holds
//! `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE, hashtext('attome-marketing/sunset:nightly'))`
//! and a second worker finds it taken and does nothing. A send's `list_id`
//! is the policy's id: a re-engagement send has no marketing list.

use attome_core::{EngineState, quote_ident};
use attome_types::AppError;
use uuid::Uuid;

/// The registered nightly job.
pub const JOB: &str = "marketing_sunset";
/// Days a re-engagement email waits for engagement before the person is
/// sunset.
pub const WAIT_DAYS: i64 = 14;
/// People one run invites back per entity.
pub const INVITES_PER_RUN: i64 = 5_000;
/// The entities the policy covers.
pub const ENTITIES: [&str; 2] = ["contact", "lead"];
/// The policy attributes [`run`] reads beyond E6-T3's.
const POLICY_ATTRIBUTES: [&str; 2] = ["reengagement_design_ref", "reengagement_purpose"];

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct SunsetRun {
    /// Whether this run did the work (false: the policy is off, or another
    /// worker holds the run).
    pub ran: bool,
    /// People sent a re-engagement email.
    pub invited: u64,
    /// People sunset.
    pub sunset: u64,
}

/// The policy as a run reads it.
#[derive(Debug, sqlx::FromRow)]
struct Policy {
    id: Uuid,
    sunset_enabled: Option<bool>,
    sunset_months: Option<f64>,
    reengagement_design_ref: Option<Uuid>,
    reengagement_purpose: Option<String>,
}

/// The months of no engagement before an invitation: the policy's, or 12
/// when it names none or a value out of range. Pure.
pub fn months_of(value: Option<f64>) -> i32 {
    match value {
        Some(m) if m.is_finite() && (1.0..=120.0).contains(&m) => m.round() as i32,
        _ => 12,
    }
}

async fn policy(state: &EngineState) -> Result<Option<Policy>, AppError> {
    let readable = state
        .entities
        .load()
        .get("marketing_deliverability_policy")
        .is_some_and(|meta| {
            POLICY_ATTRIBUTES
                .iter()
                .all(|name| meta.attrs.iter().any(|a| a.logicalname == *name))
        });
    if !readable {
        return Ok(None);
    }
    sqlx::query_as(
        "SELECT id, sunset_enabled, sunset_months::float8 AS sunset_months, \
                reengagement_design_ref, reengagement_purpose \
           FROM marketing_deliverability_policy WHERE is_active IS NOT FALSE \
          ORDER BY created_at, id LIMIT 1",
    )
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// A saved design as read: subject, locale, design JSON.
type DesignRow = (Option<String>, Option<String>, Option<String>);

/// A rendered email: subject, locale, HTML, text.
type Rendered = (String, String, String, String);

/// The rendered re-engagement email: subject, locale, HTML, text.
async fn design(state: &EngineState, id: Uuid) -> Result<Option<Rendered>, AppError> {
    let row: Option<DesignRow> = sqlx::query_as(
        "SELECT subject, locale, design FROM marketing_email_design \
          WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(subject), locale, Some(design))) = row else {
        return Ok(None);
    };
    let Ok(design) = serde_json::from_str::<crate::email_render::EmailDesign>(&design) else {
        tracing::warn!(%id, "sunset: the re-engagement design does not read; nobody is invited");
        return Ok(None);
    };
    let Ok(rendered) = crate::email_render::render(&design) else {
        tracing::warn!(%id, "sunset: the re-engagement design does not render; nobody is invited");
        return Ok(None);
    };
    Ok(Some((
        subject,
        locale.unwrap_or_else(|| "en".to_owned()),
        rendered.html,
        rendered.text,
    )))
}

/// One nightly run.
pub async fn run(state: &EngineState) -> Result<SunsetRun, AppError> {
    let mut out = SunsetRun::default();
    let Some(policy) = policy(state).await? else {
        return Ok(out);
    };
    if policy.sunset_enabled != Some(true) {
        return Ok(out);
    }
    let months = months_of(policy.sunset_months);
    let email = match (policy.reengagement_design_ref, &policy.reengagement_purpose) {
        (Some(design_id), Some(purpose)) if !purpose.trim().is_empty() => design(state, design_id)
            .await?
            .map(|d| (d, purpose.trim().to_owned())),
        _ => None,
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-marketing/sunset:nightly")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(out);
    }
    out.ran = true;
    for entity in ENTITIES {
        if !attome_core::engagement::tracks(state, entity) {
            continue;
        }
        let table = quote_ident(entity);
        if let Some(((subject, locale, html, text), purpose)) = &email {
            let people: Vec<(Uuid, String)> = sqlx::query_as(&format!(
                "SELECT t.id, trim(t.email) FROM {table} t \
                  WHERE t.is_active IS NOT FALSE AND t.marketing_sunset_at IS NULL \
                    AND t.reengagement_sent_at IS NULL \
                    AND COALESCE(t.last_marketing_engagement_at, t.created_at) \
                        < now() - make_interval(months => $1) \
                    AND position('@' IN COALESCE(t.email, '')) > 1 \
                    AND EXISTS (SELECT 1 FROM consent_current c \
                         WHERE c.subject_entity = $2 AND c.subject_id = t.id \
                           AND c.purpose_key = $3 AND c.channel IN ('email', 'any') \
                           AND c.status = 'granted') \
                  ORDER BY t.id LIMIT $4"
            ))
            .bind(months)
            .bind(entity)
            .bind(purpose)
            .bind(INVITES_PER_RUN)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if !people.is_empty() {
                let send_id: Uuid = sqlx::query_scalar(
                    "INSERT INTO email_campaign_send \
                       (list_id, subject, html_body, text_body, purpose_key, locale) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                )
                .bind(policy.id)
                .bind(subject)
                .bind(html)
                .bind(text)
                .bind(purpose)
                .bind(locale)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                let ids: Vec<Uuid> = people.iter().map(|(id, _)| *id).collect();
                let emails: Vec<String> = people.iter().map(|(_, e)| e.clone()).collect();
                let tokens: Vec<String> = people
                    .iter()
                    .map(|_| format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()))
                    .collect();
                sqlx::query(
                    "INSERT INTO email_campaign_recipient \
                       (send_id, subject_entity, subject_id, email, unsubscribe_token) \
                     SELECT $1, $2, u.id, u.email, u.token \
                       FROM unnest($3::uuid[], $4::text[], $5::text[]) AS u(id, email, token) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(send_id)
                .bind(entity)
                .bind(&ids)
                .bind(&emails)
                .bind(&tokens)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                out.invited += sqlx::query(&format!(
                    "UPDATE {table} SET reengagement_sent_at = now(), modified_at = now(), \
                            row_version = row_version + 1 WHERE id = ANY($1)"
                ))
                .bind(&ids)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
            }
        }
        out.sunset += sqlx::query(&format!(
            "UPDATE {table} SET marketing_sunset_at = now(), modified_at = now(), \
                    row_version = row_version + 1 \
              WHERE is_active IS NOT FALSE AND marketing_sunset_at IS NULL \
                AND reengagement_sent_at < now() - make_interval(days => $1) \
                AND (last_marketing_engagement_at IS NULL \
                     OR last_marketing_engagement_at < reengagement_sent_at)"
        ))
        .bind(WAIT_DAYS as i32)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    attome_db::tx::commit(tx).await?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_period_is_the_policys_or_a_year() {
        assert_eq!(months_of(Some(6.0)), 6);
        assert_eq!(months_of(None), 12);
        assert_eq!(months_of(Some(0.0)), 12);
        assert_eq!(months_of(Some(f64::NAN)), 12);
    }
}
