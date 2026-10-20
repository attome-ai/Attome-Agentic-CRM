//! Renewals and trials (roadmap F3-T9), swept nightly
//! (`EngineJob::BillingRenewalSweep`).
//!
//! **Renewals.** An active subscription whose end date falls within
//! `billing.renewal.lead_days` (default 60) is handled once per end date
//! (`subscription.renewal_handled_for`):
//!
//! - `auto`: renewed for another term at its prices raised by
//!   `billing.renewal.uplift_percent` (default 0), through
//!   `service::renew`. When the subscription names a contract, its
//!   `notice_period_days` is honoured: the renewal waits until the notice
//!   deadline (end date less the notice period) has passed, so the customer
//!   can still give notice; a contract without one renews at once.
//! - `renewal_quote`: a renewal opportunity is opened for a person to work
//!   (`service::renewal_opportunity`). No renewal quote is made: F1 has no
//!   renewal-quote function yet, which is logged.
//!
//! **Trials.** `billing.trial.reminder_days` (default 3) before a trial
//! ends, its owner gets an in-app reminder, once (`trial_reminded_on`). On
//! the trial's end date it becomes active when `billing.trial.convert` is
//! on (default) and ends otherwise. Customers are not emailed from here.
//!
//! The job acts with the platform's context, in the name of the
//! subscription's owner (the audit names them), because the renewal was
//! decided when its `renewal_mode` was set.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{Duration, NaiveDate};
use rust_decimal::Decimal;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::subscription::service;

/// Subscriptions handled per sweep.
pub const BATCH: i64 = 200;

/// The sweep's settings.
#[derive(Debug, Clone, PartialEq)]
pub struct RenewalSettings {
    pub lead_days: i64,
    pub uplift_percent: Decimal,
    pub reminder_days: i64,
    pub convert_trial: bool,
}

impl Default for RenewalSettings {
    fn default() -> Self {
        Self {
            lead_days: 60,
            uplift_percent: Decimal::ZERO,
            reminder_days: 3,
            convert_trial: true,
        }
    }
}

/// The settings as the deployment has them.
pub fn settings(state: &EngineState) -> RenewalSettings {
    let store = state.settings.load();
    let registry = attome_core::setting_registry();
    let value = |key: &str| registry.get(key).map(|d| store.resolve(d, None, None).0);
    let defaults = RenewalSettings::default();
    RenewalSettings {
        lead_days: value("billing.renewal.lead_days")
            .and_then(|v| v.as_i64())
            .unwrap_or(defaults.lead_days),
        uplift_percent: value("billing.renewal.uplift_percent")
            .and_then(|v| v.as_f64())
            .and_then(|f| Decimal::try_from(f).ok())
            .unwrap_or(defaults.uplift_percent),
        reminder_days: value("billing.trial.reminder_days")
            .and_then(|v| v.as_i64())
            .unwrap_or(defaults.reminder_days),
        convert_trial: value("billing.trial.convert")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.convert_trial),
    }
}

/// Whether an auto renewal may run today: once the contract's notice
/// deadline has passed, or at once without a notice period. Pure.
pub fn notice_passed(end: NaiveDate, notice_days: Option<i64>, today: NaiveDate) -> bool {
    match notice_days.filter(|d| *d > 0) {
        Some(days) => today > end - Duration::days(days),
        None => true,
    }
}

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RenewalRun {
    pub renewed: u64,
    pub opportunities: u64,
    pub reminders: u64,
    pub trials_converted: u64,
    pub trials_ended: u64,
}

/// Both sweeps.
pub async fn run(state: &EngineState, today: NaiveDate) -> Result<RenewalRun, AppError> {
    let s = settings(state);
    let mut out = renewal_sweep(state, &s, today).await?;
    let trials = trial_sweep(state, &s, today).await?;
    out.reminders = trials.reminders;
    out.trials_converted = trials.trials_converted;
    out.trials_ended = trials.trials_ended;
    Ok(out)
}

type DueRow = (Uuid, Option<String>, Option<Uuid>, NaiveDate, Option<Uuid>);

/// Renews or opens renewal opportunities for subscriptions ending soon.
pub async fn renewal_sweep(
    state: &EngineState,
    s: &RenewalSettings,
    today: NaiveDate,
) -> Result<RenewalRun, AppError> {
    let mut out = RenewalRun::default();
    if state.entities.load().get("subscription").is_none() {
        return Ok(out);
    }
    let due: Vec<DueRow> = sqlx::query_as(
        "SELECT id, renewal_mode, owner_ref, end_date, contract_ref FROM subscription \
          WHERE status = 'active' AND renewal_mode IN ('auto', 'renewal_quote') \
            AND end_date >= $1 AND end_date <= $2 \
            AND (renewal_handled_for IS NULL OR renewal_handled_for <> end_date) \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY end_date, id LIMIT $3",
    )
    .bind(today)
    .bind(today + Duration::days(s.lead_days.max(0)))
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (id, mode, owner, end, contract) in due {
        let ctx = attome_records::entity_crud::admin_security_context(owner.unwrap_or(Uuid::nil()));
        let result = match mode.as_deref() {
            Some("auto") => {
                let notice = match contract {
                    Some(c) => notice_days(state, c).await?,
                    None => None,
                };
                if !notice_passed(end, notice, today) {
                    continue;
                }
                service::renew(state, &ctx, id, s.uplift_percent)
                    .await
                    .map(|_| out.renewed += 1)
            }
            _ => service::renewal_opportunity(state, &ctx, id)
                .await
                .map(|opened| {
                    if opened.is_some() {
                        out.opportunities += 1;
                        tracing::info!(
                            subscription = %id,
                            "renewal: opportunity opened; no renewal quote, F1 has none yet"
                        );
                    }
                }),
        };
        // One subscription failing (a lock held, a bad record) does not stop
        // the others; it is tried again tomorrow.
        if let Err(error) = result {
            tracing::warn!(subscription = %id, %error, "renewal: subscription not handled");
        }
    }
    Ok(out)
}

/// The contract's notice period in days, when it has one.
async fn notice_days(state: &EngineState, contract: Uuid) -> Result<Option<i64>, AppError> {
    if state.entities.load().get("contract").is_none_or(|m| {
        !m.attrs
            .iter()
            .any(|a| a.logicalname == "notice_period_days")
    }) {
        return Ok(None);
    }
    let days: Option<Option<f64>> =
        sqlx::query_scalar("SELECT notice_period_days::float8 FROM contract WHERE id = $1")
            .bind(contract)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(days.flatten().map(|d| d as i64))
}

type TrialRow = (Uuid, Option<Uuid>, NaiveDate, Option<NaiveDate>, String);

/// Reminds owners of trials ending soon, and converts or ends trials that
/// have ended.
pub async fn trial_sweep(
    state: &EngineState,
    s: &RenewalSettings,
    today: NaiveDate,
) -> Result<RenewalRun, AppError> {
    let mut out = RenewalRun::default();
    if state.entities.load().get("subscription").is_none() {
        return Ok(out);
    }
    let trials: Vec<TrialRow> = sqlx::query_as(
        "SELECT id, owner_ref, trial_end_date, trial_reminded_on, name FROM subscription \
          WHERE status = 'trial' AND trial_end_date IS NOT NULL AND trial_end_date <= $1 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY trial_end_date, id LIMIT $2",
    )
    .bind(today + Duration::days(s.reminder_days.max(0)))
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (id, owner, trial_end, reminded, name) in trials {
        let ctx = attome_records::entity_crud::admin_security_context(owner.unwrap_or(Uuid::nil()));
        let result = if trial_end <= today {
            let mut fields = Map::new();
            let status = if s.convert_trial { "active" } else { "ended" };
            fields.insert("status".into(), Value::String(status.into()));
            let event = if s.convert_trial {
                "billing.subscription.trial_converted"
            } else {
                "billing.subscription.trial_ended"
            };
            service::set_fields(state, &ctx, id, fields, event)
                .await
                .map(|()| {
                    if s.convert_trial {
                        out.trials_converted += 1;
                    } else {
                        out.trials_ended += 1;
                    }
                })
        } else if reminded.is_none() {
            let mut fields = Map::new();
            fields.insert("trial_reminded_on".into(), Value::String(today.to_string()));
            let marked = service::set_fields(
                state,
                &ctx,
                id,
                fields,
                "billing.subscription.trial_reminded",
            )
            .await;
            if marked.is_ok()
                && let Some(user) = owner
            {
                remind(state, user, id, &name, trial_end).await;
                out.reminders += 1;
            }
            marked
        } else {
            Ok(())
        };
        if let Err(error) = result {
            tracing::warn!(subscription = %id, %error, "trial: subscription not handled");
        }
    }
    Ok(out)
}

/// One in-app reminder to the trial's owner; a failure is logged, never
/// fatal, since the reminder is already marked.
async fn remind(
    state: &EngineState,
    user: Uuid,
    subscription: Uuid,
    name: &str,
    trial_end: NaiveDate,
) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some(format!("Trial ending: {name}")),
        body_html: None,
        body_text: Some(format!(
            "The trial of {name} ends on {trial_end}. Check with the customer before it converts."
        )),
        route: Some(format!("/xrm/entity/subscription/form?id={subscription}")),
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
        tracing::warn!(%subscription, %user, %error, "trial: reminder failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn auto_renewal_waits_for_the_notice_deadline() {
        let end = d(2027, 12, 31);
        assert!(notice_passed(end, None, d(2027, 11, 1)));
        assert!(notice_passed(end, Some(0), d(2027, 11, 1)));
        assert!(!notice_passed(end, Some(30), d(2027, 11, 1)));
        assert!(notice_passed(end, Some(30), d(2027, 12, 2)));
    }

    #[test]
    fn renewal_prices_are_uplifted() {
        assert_eq!(
            service::uplifted(Decimal::from(100), Decimal::from(5)),
            Decimal::from(105)
        );
        assert_eq!(
            service::uplifted(Decimal::new(9999, 2), Decimal::ZERO),
            Decimal::new(9999, 2)
        );
    }
}
