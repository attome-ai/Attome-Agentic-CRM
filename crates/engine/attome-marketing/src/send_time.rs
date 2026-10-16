//! Send-time optimisation (roadmap E5-T1): each contact's best hour from
//! when they opened past emails, read in the contact's own time zone, and the
//! moment to send inside a campaign's window. Pure: the caller loads the
//! opens and stores the schedule.
//!
//! The histogram weighs recent opens more (a half-life in days), so a
//! contact whose habits changed moves with them. A contact with too few opens
//! gets the campaign's default hour. A hold-out share of contacts always gets
//! the default hour, so the gain can be measured; who is held out is decided
//! from the contact id, so it is stable between runs.

use chrono::{DateTime, Duration, NaiveTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use uuid::Uuid;

/// Settings of one campaign's optimisation.
#[derive(Debug, Clone)]
pub struct SendTimePolicy {
    /// Hour (0-23, contact's time) used without enough history.
    pub default_hour: u32,
    /// Opens needed before a contact's own hour is trusted.
    pub min_opens: usize,
    /// Days after which an open counts half.
    pub half_life_days: f64,
    /// Share of contacts, 0 to 1, always sent at the default hour.
    pub holdout_share: f64,
}

impl Default for SendTimePolicy {
    fn default() -> Self {
        Self {
            default_hour: 10,
            min_opens: 3,
            half_life_days: 90.0,
            holdout_share: 0.1,
        }
    }
}

/// Why a contact got its hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HourSource {
    History,
    Default,
    Holdout,
}

/// A contact's chosen hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BestHour {
    pub hour: u32,
    pub source: HourSource,
}

/// The weighted share of opens per local hour.
pub fn open_histogram(
    opens: &[DateTime<Utc>],
    tz: Tz,
    now: DateTime<Utc>,
    half_life_days: f64,
) -> [f64; 24] {
    let mut bins = [0.0; 24];
    for open in opens {
        let age_days = (now - *open).num_seconds().max(0) as f64 / 86_400.0;
        let weight = if half_life_days > 0.0 {
            0.5f64.powf(age_days / half_life_days)
        } else {
            1.0
        };
        let hour = open.with_timezone(&tz).hour() as usize;
        bins[hour] += weight;
    }
    bins
}

/// Whether `contact` is in the hold-out: a stable share by contact id.
pub fn in_holdout(contact: Uuid, share: f64) -> bool {
    if share <= 0.0 {
        return false;
    }
    let bytes = contact.as_bytes();
    let bucket = u16::from_be_bytes([bytes[14], bytes[15]]) % 10_000;
    f64::from(bucket) < share * 10_000.0
}

/// A contact's best hour, in its own time zone.
pub fn best_hour(
    contact: Uuid,
    opens: &[DateTime<Utc>],
    tz: Tz,
    now: DateTime<Utc>,
    policy: &SendTimePolicy,
) -> BestHour {
    if in_holdout(contact, policy.holdout_share) {
        return BestHour {
            hour: policy.default_hour,
            source: HourSource::Holdout,
        };
    }
    if opens.len() < policy.min_opens {
        return BestHour {
            hour: policy.default_hour,
            source: HourSource::Default,
        };
    }
    let bins = open_histogram(opens, tz, now, policy.half_life_days);
    // Ties go to the hour nearest the default, then the earlier hour.
    let mut best = policy.default_hour;
    let mut best_weight = f64::MIN;
    for (hour, weight) in bins.iter().enumerate() {
        let hour = hour as u32;
        let better = *weight > best_weight + 1e-12
            || ((*weight - best_weight).abs() <= 1e-12
                && hour.abs_diff(policy.default_hour) < best.abs_diff(policy.default_hour));
        if better {
            best = hour;
            best_weight = *weight;
        }
    }
    BestHour {
        hour: best,
        source: HourSource::History,
    }
}

/// When to send to a contact whose best local hour is `hour`: the first
/// such hour at or after `window_start` and before `window_end`, else
/// `window_start` (the window is too short to reach the hour).
pub fn schedule_in_window(
    hour: u32,
    tz: Tz,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> DateTime<Utc> {
    let Some(time) = NaiveTime::from_hms_opt(hour.min(23), 0, 0) else {
        return window_start;
    };
    let local_start = window_start.with_timezone(&tz);
    for day in 0..8 {
        let date = local_start.date_naive() + Duration::days(day);
        let Some(candidate) = tz.from_local_datetime(&date.and_time(time)).earliest() else {
            continue;
        };
        let candidate = candidate.with_timezone(&Utc);
        if candidate >= window_end {
            break;
        }
        if candidate >= window_start {
            return candidate;
        }
    }
    window_start
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn not_held_out() -> Uuid {
        // Last two bytes 0xFFFF: bucket 5535, outside a 10% hold-out.
        Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0xFF, 0xFF])
    }

    #[test]
    fn best_hour_follows_local_opens() {
        let riyadh: Tz = "Asia/Riyadh".parse().unwrap();
        // 18:00 UTC is 21:00 in Riyadh.
        let opens = vec![
            at("2026-10-01T18:05:00Z"),
            at("2026-10-02T18:10:00Z"),
            at("2026-10-03T18:20:00Z"),
            at("2026-10-04T07:00:00Z"),
        ];
        let got = best_hour(
            not_held_out(),
            &opens,
            riyadh,
            at("2026-10-10T00:00:00Z"),
            &SendTimePolicy::default(),
        );
        assert_eq!(
            got,
            BestHour {
                hour: 21,
                source: HourSource::History
            }
        );
    }

    #[test]
    fn too_few_opens_falls_back_to_the_default() {
        let got = best_hour(
            not_held_out(),
            &[at("2026-10-01T18:05:00Z")],
            chrono_tz::UTC,
            at("2026-10-10T00:00:00Z"),
            &SendTimePolicy::default(),
        );
        assert_eq!(
            got,
            BestHour {
                hour: 10,
                source: HourSource::Default
            }
        );
    }

    #[test]
    fn recent_opens_outweigh_old_ones() {
        let mut opens = vec![at("2025-01-01T08:00:00Z"); 3];
        opens.extend(vec![at("2026-10-08T20:00:00Z"); 2]);
        let policy = SendTimePolicy {
            half_life_days: 30.0,
            ..SendTimePolicy::default()
        };
        let got = best_hour(
            not_held_out(),
            &opens,
            chrono_tz::UTC,
            at("2026-10-10T00:00:00Z"),
            &policy,
        );
        assert_eq!(got.hour, 20);
    }

    #[test]
    fn holdout_is_stable_and_near_its_share() {
        let held = (0u32..10_000)
            .filter(|i| {
                let mut b = [0u8; 16];
                b[12..16].copy_from_slice(&i.to_be_bytes());
                in_holdout(Uuid::from_bytes(b), 0.1)
            })
            .count();
        assert_eq!(held, 1_000);
        assert!(!in_holdout(not_held_out(), 0.0));
    }

    #[test]
    fn schedule_lands_inside_the_window() {
        let riyadh: Tz = "Asia/Riyadh".parse().unwrap();
        let start = at("2026-10-10T10:00:00Z"); // 13:00 Riyadh
        let end = at("2026-10-12T00:00:00Z");
        // 09:00 Riyadh has passed today: tomorrow 06:00 UTC.
        assert_eq!(
            schedule_in_window(9, riyadh, start, end),
            at("2026-10-11T06:00:00Z")
        );
        // 21:00 Riyadh today: 18:00 UTC.
        assert_eq!(
            schedule_in_window(21, riyadh, start, end),
            at("2026-10-10T18:00:00Z")
        );
        // A window too short to reach the hour sends at its start.
        assert_eq!(
            schedule_in_window(9, riyadh, start, at("2026-10-10T12:00:00Z")),
            start
        );
    }
}
