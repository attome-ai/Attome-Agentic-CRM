//! E8-T6: whether a journey may message a person now.
//!
//! [`check`] reads, in order: consent for the step's purpose on its channel
//! (`consent_current`, granted for the channel or `any`); for email, the
//! suppression list; the sunset policy (`marketing_sunset_at`, E6-T9); the
//! quiet hours and weekend days of `marketing.journey_quiet_hours` in the
//! deployment's time zone; and the weekly cap (`marketing.weekly_message_cap`,
//! the cap campaigns already honour, 3 by default) over the last seven days
//! of journey messages, campaign emails and campaign SMS together. The first
//! that fails decides: [`RuleVerdict::Blocked`], or for quiet hours
//! [`RuleVerdict::Deferred`] to the first allowed minute. [`verdict`] is the
//! pure decision.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Datelike, Duration, NaiveTime, Timelike, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::sms_campaign::QuietHours;

/// The quiet-hours setting.
pub const QUIET_SETTING: &str = "marketing.journey_quiet_hours";

/// What the rules say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleVerdict {
    Allowed,
    Blocked(String),
    Deferred(DateTime<Utc>),
}

/// The facts [`verdict`] decides on.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub consent: bool,
    pub suppressed: bool,
    pub sunset: bool,
    /// The first allowed moment when `at` is inside quiet hours or a
    /// weekend day.
    pub quiet_until: Option<DateTime<Utc>>,
    pub sent_last_7_days: i64,
    pub cap: i64,
}

/// The decision, in the rules' order. Pure.
pub fn verdict(facts: &Facts) -> RuleVerdict {
    if !facts.consent {
        return RuleVerdict::Blocked("no_consent".into());
    }
    if facts.suppressed {
        return RuleVerdict::Blocked("suppressed".into());
    }
    if facts.sunset {
        return RuleVerdict::Blocked("sunset".into());
    }
    if let Some(until) = facts.quiet_until {
        return RuleVerdict::Deferred(until);
    }
    if crate::email_campaign::over_cap(facts.sent_last_7_days, facts.cap) {
        return RuleVerdict::Blocked("frequency_cap".into());
    }
    RuleVerdict::Allowed
}

/// The quiet window and weekend days (0 Monday .. 6 Sunday) from the
/// setting's value; `None` when it holds neither. Pure.
pub fn quiet_of(setting: &Value) -> Option<(Option<QuietHours>, Vec<u32>)> {
    let time = |k: &str| {
        setting
            .get(k)
            .and_then(Value::as_str)
            .and_then(|t| NaiveTime::parse_from_str(t, "%H:%M").ok())
    };
    let hours = match (time("start"), time("end")) {
        (Some(start), Some(end)) => Some(QuietHours { start, end }),
        _ => None,
    };
    let weekend: Vec<u32> = setting
        .get("weekend_days")
        .and_then(Value::as_array)
        .map(|days| {
            days.iter()
                .filter_map(Value::as_u64)
                .filter(|d| *d < 7)
                .map(|d| d as u32)
                .collect()
        })
        .unwrap_or_default();
    (hours.is_some() || !weekend.is_empty()).then_some((hours, weekend))
}

/// The first minute at or after `at` outside the quiet window and the
/// weekend days, in `zone`; `None` when `at` itself is allowed. Searches a
/// week ahead, minute by minute in 15-minute steps. Pure.
pub fn next_allowed(
    at: DateTime<Utc>,
    hours: Option<&QuietHours>,
    weekend: &[u32],
    zone: chrono_tz::Tz,
) -> Option<DateTime<Utc>> {
    let blocked = |t: DateTime<Utc>| {
        let local = t.with_timezone(&zone);
        let day = local.weekday().num_days_from_monday();
        let minute = NaiveTime::from_hms_opt(local.hour(), local.minute(), 0).unwrap_or_default();
        weekend.contains(&day) || hours.is_some_and(|h| h.holds(minute))
    };
    if !blocked(at) {
        return None;
    }
    let mut t = at;
    for _ in 0..(7 * 24 * 4) {
        t += Duration::minutes(15);
        if !blocked(t) {
            return Some(t);
        }
    }
    None
}

fn setting(state: &EngineState, key: &str) -> Value {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(key)
        .map(|d| store.resolve(d, None, None).0)
        .unwrap_or(Value::Null)
}

/// Checks the rules for messaging `person` (of `entity`, at `address`) on
/// `channel` for `purpose` at `at`.
pub async fn check(
    state: &EngineState,
    entity: &str,
    person: Uuid,
    address: &str,
    channel: &str,
    purpose: &str,
    at: DateTime<Utc>,
) -> Result<RuleVerdict, AppError> {
    let db = &state.base.db;
    let consent: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM consent_current c \
          WHERE c.subject_entity = $1 AND c.subject_id = $2 AND c.purpose_key = $3 \
            AND c.channel IN ($4, 'any') AND c.status = 'granted')",
    )
    .bind(entity)
    .bind(person)
    .bind(purpose)
    .bind(channel)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let suppressed = channel == "email"
        && attome_email::suppression::is_suppressed(db, address)
            .await
            .map_err(AppError::internal)?;
    let sunset = if attome_core::engagement::tracks(state, entity) {
        sqlx::query_scalar::<_, bool>(&format!(
            "SELECT marketing_sunset_at IS NOT NULL FROM {} WHERE id = $1",
            attome_core::quote_ident(entity)
        ))
        .bind(person)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .unwrap_or(false)
    } else {
        false
    };
    let quiet_until = quiet_of(&setting(state, QUIET_SETTING)).and_then(|(hours, weekend)| {
        next_allowed(
            at,
            hours.as_ref(),
            &weekend,
            crate::sms_campaign::deployment_zone(state),
        )
    });
    let sent_last_7_days: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM marketing_message_log \
                  WHERE person_id = $2 AND NOT is_test AND sent_at > now() - interval '7 days') \
              + (SELECT COUNT(*) FROM email_campaign_recipient \
                  WHERE subject_entity = $1 AND subject_id = $2 AND status = 'sent' \
                    AND attempted_at > now() - interval '7 days') \
              + (SELECT COUNT(*) FROM sms_campaign_recipient \
                  WHERE subject_entity = $1 AND subject_id = $2 AND status = 'sent' \
                    AND attempted_at > now() - interval '7 days')",
    )
    .bind(entity)
    .bind(person)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(verdict(&Facts {
        consent,
        suppressed,
        sunset,
        quiet_until,
        sent_last_7_days,
        cap: crate::email_campaign::weekly_cap(state),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Facts {
        Facts {
            consent: true,
            cap: 3,
            ..Facts::default()
        }
    }

    #[test]
    fn no_consent_blocks() {
        let facts = Facts {
            consent: false,
            ..allowed()
        };
        assert_eq!(verdict(&facts), RuleVerdict::Blocked("no_consent".into()));
        assert_eq!(verdict(&allowed()), RuleVerdict::Allowed);
    }

    #[test]
    fn quiet_hours_defers() {
        let quiet = QuietHours {
            start: NaiveTime::from_hms_opt(21, 0, 0).unwrap(),
            end: NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
        };
        // 23:00 UTC on Monday 2 November 2026.
        let night = DateTime::parse_from_rfc3339("2026-11-02T23:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let until = next_allowed(night, Some(&quiet), &[], chrono_tz::UTC).unwrap();
        assert_eq!(until.hour(), 8);
        let facts = Facts {
            quiet_until: Some(until),
            ..allowed()
        };
        assert_eq!(verdict(&facts), RuleVerdict::Deferred(until));
        let noon = night - Duration::hours(11);
        assert_eq!(next_allowed(noon, Some(&quiet), &[], chrono_tz::UTC), None);
        // Saturday (5) as a weekend day moves Saturday noon to Sunday.
        let saturday = DateTime::parse_from_rfc3339("2026-11-07T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let after = next_allowed(saturday, None, &[5], chrono_tz::UTC).unwrap();
        assert_eq!(after.weekday().num_days_from_monday(), 6);
    }

    #[test]
    fn frequency_cap_blocks_fourth_message() {
        let third = Facts {
            sent_last_7_days: 2,
            ..allowed()
        };
        assert_eq!(verdict(&third), RuleVerdict::Allowed);
        let fourth = Facts {
            sent_last_7_days: 3,
            ..allowed()
        };
        assert_eq!(
            verdict(&fourth),
            RuleVerdict::Blocked("frequency_cap".into())
        );
    }
}
