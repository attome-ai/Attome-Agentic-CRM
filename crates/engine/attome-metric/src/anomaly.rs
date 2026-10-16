//! Seasonal baselines and departures (roadmap O4-T1), pure. A series of
//! timestamped values (calls per hour, tickets opened, orders) has a normal
//! level for each hour of the week; a value is unusual when it is far from
//! that hour's median, measured in median absolute deviations (MAD), which
//! one past outlier cannot distort the way a mean and standard deviation
//! can.
//!
//! A baseline needs at least [`MIN_WEEKS`] weeks of history; an hour of the
//! week with fewer than [`MIN_WEEKS`] values has no baseline and scores
//! nothing.

use std::collections::HashMap;

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::Serialize;

/// The least history a baseline needs, in weeks.
pub const MIN_WEEKS: usize = 4;

/// The scale factor that makes the MAD comparable to a standard deviation
/// for normal data.
const MAD_SCALE: f64 = 1.4826;

/// Hour of the week: 0 is Monday 00:00 to 01:00, 167 Sunday 23:00.
pub fn hour_of_week(at: DateTime<Utc>) -> usize {
    at.weekday().num_days_from_monday() as usize * 24 + at.hour() as usize
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// One hour of the week's normal level.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Slot {
    pub median: f64,
    pub mad: f64,
    pub samples: usize,
}

/// The baseline of a series: a slot per hour of the week that has enough
/// history.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Baseline {
    slots: HashMap<usize, Slot>,
}

impl Baseline {
    /// Builds the baseline from history; `None` when it spans less than
    /// [`MIN_WEEKS`] weeks.
    pub fn build(history: &[(DateTime<Utc>, f64)]) -> Option<Self> {
        let first = history.iter().map(|(t, _)| *t).min()?;
        let last = history.iter().map(|(t, _)| *t).max()?;
        if (last - first).num_days() < (MIN_WEEKS as i64 * 7) - 1 {
            return None;
        }
        let mut by_slot: HashMap<usize, Vec<f64>> = HashMap::new();
        for (at, value) in history {
            if value.is_finite() {
                by_slot.entry(hour_of_week(*at)).or_default().push(*value);
            }
        }
        let slots = by_slot
            .into_iter()
            .filter(|(_, values)| values.len() >= MIN_WEEKS)
            .map(|(slot, mut values)| {
                let m = median(&mut values);
                let mut deviations: Vec<f64> = values.iter().map(|v| (v - m).abs()).collect();
                let mad = median(&mut deviations);
                (
                    slot,
                    Slot {
                        median: m,
                        mad,
                        samples: values.len(),
                    },
                )
            })
            .collect();
        Some(Self { slots })
    }

    pub fn slot(&self, at: DateTime<Utc>) -> Option<&Slot> {
        self.slots.get(&hour_of_week(at))
    }

    /// How unusual `value` is at `at`: its distance from the hour's median
    /// in scaled MADs, signed (above is positive). A flat history (MAD 0)
    /// scores any change as far out. `None` without a baseline for the hour.
    pub fn score(&self, at: DateTime<Utc>, value: f64) -> Option<f64> {
        let slot = self.slot(at)?;
        let spread = slot.mad * MAD_SCALE;
        let distance = value - slot.median;
        if spread > 0.0 {
            Some(distance / spread)
        } else if distance == 0.0 {
            Some(0.0)
        } else {
            Some(distance.signum() * f64::INFINITY)
        }
    }
}

/// A value departing from its baseline.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Departure {
    pub at: DateTime<Utc>,
    pub value: f64,
    pub expected: f64,
    pub score: f64,
}

/// The points of `recent` whose score is at least `threshold` either way
/// (3.5 is the usual cut for modified z-scores).
pub fn departures(
    baseline: &Baseline,
    recent: &[(DateTime<Utc>, f64)],
    threshold: f64,
) -> Vec<Departure> {
    recent
        .iter()
        .filter_map(|(at, value)| {
            let score = baseline.score(*at, *value)?;
            let expected = baseline.slot(*at)?.median;
            (score.abs() >= threshold).then_some(Departure {
                at: *at,
                value: *value,
                expected,
                score,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn monday() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 7, 0, 0, 0)
            .single()
            .unwrap_or_default()
    }

    /// Six weeks of hourly values: 10 by night, 100 at 10:00 on weekdays,
    /// with a little noise.
    fn history() -> Vec<(DateTime<Utc>, f64)> {
        (0..6 * 7 * 24)
            .map(|h| {
                let at = monday() + Duration::hours(h);
                let busy = at.hour() == 10 && at.weekday().num_days_from_monday() < 5;
                let noise = (h % 3) as f64;
                (at, if busy { 100.0 + noise } else { 10.0 + noise })
            })
            .collect()
    }

    #[test]
    fn baseline_follows_the_hour_of_the_week() {
        let baseline = Baseline::build(&history()).unwrap_or_default();
        let tuesday_ten = monday() + Duration::days(43) + Duration::hours(10);
        let slot = baseline.slot(tuesday_ten).copied();
        assert!(slot.is_some_and(|s| (s.median - 101.0).abs() <= 1.0));
        let sunday_ten = monday() + Duration::days(48) + Duration::hours(10);
        assert!(baseline.slot(sunday_ten).is_some_and(|s| s.median < 20.0));
    }

    #[test]
    fn departures_are_scored_robustly() {
        let baseline = Baseline::build(&history()).unwrap_or_default();
        let tuesday_ten = monday() + Duration::days(43) + Duration::hours(10);
        let quiet_night = monday() + Duration::days(43) + Duration::hours(3);
        let recent = [
            (tuesday_ten, 101.0),
            (quiet_night, 80.0),
            (tuesday_ten, 20.0),
        ];
        let found = departures(&baseline, &recent, 3.5);
        assert_eq!(found.len(), 2, "a normal busy hour is not a departure");
        assert!(found[0].score > 3.5, "a busy night is above");
        assert!(found[1].score < -3.5, "a quiet busy hour is below");
    }

    #[test]
    fn too_little_history_has_no_baseline() {
        let short: Vec<_> = history().into_iter().take(3 * 7 * 24).collect();
        assert_eq!(Baseline::build(&short), None);
        assert_eq!(Baseline::build(&[]), None);
    }
}
