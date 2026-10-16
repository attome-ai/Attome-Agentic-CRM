//! Shift rules (roadmap G17-T4), pure: one person's week of shifts against
//! the rule set — hours per day and per week, rest between shifts, night
//! shifts, days off — and, for a person on the Ramadan pattern, the shorter
//! Ramadan day. Each broken rule is one [`RuleBreach`] naming the shifts.

use std::collections::{BTreeMap, BTreeSet};

use attome_calendar::BusinessCalendar;
use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Timelike, Weekday};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One scheduled shift, in the person's local time; `end` after `start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shift {
    pub id: Uuid,
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
}

impl Shift {
    fn hours(&self) -> f64 {
        (self.end - self.start).num_minutes() as f64 / 60.0
    }

    /// The day a shift counts against: the day it starts.
    fn day(&self) -> NaiveDate {
        self.start.date()
    }
}

/// The `xrm_wfm_rule_set` limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSet {
    pub max_hours_day: f64,
    pub max_hours_week: f64,
    pub min_rest_hours: f64,
    /// The most night shifts a week.
    pub max_nights_week: u32,
    /// A night shift has any part between these local hours (e.g. 22 to 6).
    pub night_from_hour: u32,
    pub night_to_hour: u32,
    /// The fewest days without a shift in a week.
    pub min_days_off_week: u32,
    /// The longest day during Ramadan, for a person on the Ramadan pattern.
    pub ramadan_max_hours_day: f64,
}

/// Where the week sits: the person's working calendar (whose working days
/// fix where the week starts) and, when it applies, Ramadan.
#[derive(Debug, Clone, Copy)]
pub struct WeekContext<'a> {
    pub calendar: &'a BusinessCalendar,
    /// The deployment calendar's Ramadan exception range, inclusive.
    pub ramadan: Option<(NaiveDate, NaiveDate)>,
    /// The person works the Ramadan pattern.
    pub ramadan_pattern: bool,
}

/// One broken rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleBreach {
    /// `max_day`, `max_week`, `min_rest`, `max_nights`, `days_off` or `ramadan`.
    pub code: &'static str,
    pub shift_ids: Vec<Uuid>,
}

fn is_night(shift: &Shift, rules: &RuleSet) -> bool {
    let mut at = shift.start;
    while at < shift.end {
        let hour = at.hour();
        let night = if rules.night_from_hour > rules.night_to_hour {
            hour >= rules.night_from_hour || hour < rules.night_to_hour
        } else {
            hour >= rules.night_from_hour && hour < rules.night_to_hour
        };
        if night {
            return true;
        }
        at += Duration::hours(1);
        at = at.with_minute(0).unwrap_or(at);
    }
    false
}

/// The first day of the calendar's working week: the working day that
/// follows a day off (Sunday for a Sunday-Thursday week, Monday for a
/// Monday-Friday one); Monday when every day works or none does.
pub fn week_start(calendar: &BusinessCalendar) -> Weekday {
    let working = calendar.working_days();
    let mut day = Weekday::Mon;
    for _ in 0..7 {
        if working.contains(&day) && !working.contains(&day.pred()) {
            return day;
        }
        day = day.succ();
    }
    Weekday::Mon
}

/// Every rule `week` breaks.
pub fn check(week: &[Shift], rules: &RuleSet, ctx: &WeekContext<'_>) -> Vec<RuleBreach> {
    let mut breaches = Vec::new();
    let mut shifts: Vec<&Shift> = week.iter().collect();
    shifts.sort_by_key(|s| s.start);

    // Hours per day, and the Ramadan day for a person on that pattern.
    let mut by_day: BTreeMap<NaiveDate, Vec<&Shift>> = BTreeMap::new();
    for s in &shifts {
        by_day.entry(s.day()).or_default().push(s);
    }
    let in_ramadan = |day: NaiveDate| {
        ctx.ramadan_pattern
            && ctx
                .ramadan
                .is_some_and(|(from, to)| day >= from && day <= to)
    };
    for (day, day_shifts) in &by_day {
        let hours: f64 = day_shifts.iter().map(|s| s.hours()).sum();
        let ids = || day_shifts.iter().map(|s| s.id).collect::<Vec<_>>();
        if in_ramadan(*day) {
            if hours > rules.ramadan_max_hours_day {
                breaches.push(RuleBreach {
                    code: "ramadan",
                    shift_ids: ids(),
                });
            }
        } else if hours > rules.max_hours_day {
            breaches.push(RuleBreach {
                code: "max_day",
                shift_ids: ids(),
            });
        }
    }

    let week_hours: f64 = shifts.iter().map(|s| s.hours()).sum();
    if week_hours > rules.max_hours_week {
        breaches.push(RuleBreach {
            code: "max_week",
            shift_ids: shifts.iter().map(|s| s.id).collect(),
        });
    }

    let short_rest: Vec<Uuid> = shifts
        .windows(2)
        .filter(|pair| {
            let rest = (pair[1].start - pair[0].end).num_minutes() as f64 / 60.0;
            rest < rules.min_rest_hours
        })
        .map(|pair| pair[1].id)
        .collect();
    if !short_rest.is_empty() {
        breaches.push(RuleBreach {
            code: "min_rest",
            shift_ids: short_rest,
        });
    }

    let nights: Vec<Uuid> = shifts
        .iter()
        .filter(|s| is_night(s, rules))
        .map(|s| s.id)
        .collect();
    if nights.len() as u32 > rules.max_nights_week {
        breaches.push(RuleBreach {
            code: "max_nights",
            shift_ids: nights,
        });
    }

    // Days off, counted over the calendar's own week (Sunday-Thursday or
    // Monday-Friday) that holds the first shift.
    if let Some(first) = shifts.first() {
        let start_day = week_start(ctx.calendar);
        let offset = (7 + first.day().weekday().num_days_from_monday()
            - start_day.num_days_from_monday())
            % 7;
        let week_from = first.day() - Duration::days(i64::from(offset));
        let worked: BTreeSet<NaiveDate> = shifts
            .iter()
            .map(|s| s.day())
            .filter(|d| *d >= week_from && *d < week_from + Duration::days(7))
            .collect();
        let days_off = 7 - worked.len() as u32;
        if days_off < rules.min_days_off_week {
            breaches.push(RuleBreach {
                code: "days_off",
                shift_ids: shifts.iter().map(|s| s.id).collect(),
            });
        }
    }

    breaches
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_calendar::TimeRange;
    use std::collections::HashSet;

    fn calendar(days: &[Weekday]) -> BusinessCalendar {
        let set: HashSet<Weekday> = days.iter().copied().collect();
        BusinessCalendar::simple(chrono_tz::UTC, set, TimeRange::new(8 * 60, 17 * 60))
            .expect("calendar")
    }

    fn sun_thu() -> BusinessCalendar {
        calendar(&[
            Weekday::Sun,
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
        ])
    }

    fn rules() -> RuleSet {
        RuleSet {
            max_hours_day: 9.0,
            max_hours_week: 45.0,
            min_rest_hours: 11.0,
            max_nights_week: 2,
            night_from_hour: 22,
            night_to_hour: 6,
            min_days_off_week: 2,
            ramadan_max_hours_day: 6.0,
        }
    }

    fn shift(day: u32, from: u32, to: u32) -> Shift {
        let date = NaiveDate::from_ymd_opt(2027, 1, day).expect("date");
        let start = date.and_hms_opt(from, 0, 0).expect("time");
        let end = if to > from {
            date.and_hms_opt(to, 0, 0).expect("time")
        } else {
            (date + Duration::days(1))
                .and_hms_opt(to, 0, 0)
                .expect("time")
        };
        Shift {
            id: Uuid::now_v7(),
            start,
            end,
        }
    }

    /// Sunday 3 to Thursday 7 January 2027, 08:00-16:00.
    fn normal_week() -> Vec<Shift> {
        (3..=7).map(|d| shift(d, 8, 16)).collect()
    }

    fn codes(week: &[Shift], ctx: &WeekContext<'_>) -> Vec<&'static str> {
        check(week, &rules(), ctx)
            .into_iter()
            .map(|b| b.code)
            .collect()
    }

    fn ctx(cal: &BusinessCalendar) -> WeekContext<'_> {
        WeekContext {
            calendar: cal,
            ramadan: None,
            ramadan_pattern: false,
        }
    }

    #[test]
    fn max_day_passes() {
        let cal = sun_thu();
        assert!(codes(&normal_week(), &ctx(&cal)).is_empty());
    }

    #[test]
    fn max_day_breaches() {
        let cal = sun_thu();
        let mut week = normal_week();
        week[0] = shift(3, 7, 18);
        assert_eq!(codes(&week, &ctx(&cal)), vec!["max_day"]);
    }

    #[test]
    fn max_week_passes() {
        let cal = sun_thu();
        assert!(!codes(&normal_week(), &ctx(&cal)).contains(&"max_week"));
    }

    #[test]
    fn max_week_breaches() {
        let cal = sun_thu();
        let week: Vec<Shift> = (3..=7).map(|d| shift(d, 7, 16)).collect();
        let mut r = rules();
        r.max_hours_week = 40.0;
        let got: Vec<&str> = check(&week, &r, &ctx(&cal))
            .into_iter()
            .map(|b| b.code)
            .collect();
        assert_eq!(got, vec!["max_week"]);
    }

    #[test]
    fn min_rest_passes() {
        let cal = sun_thu();
        assert!(!codes(&normal_week(), &ctx(&cal)).contains(&"min_rest"));
    }

    #[test]
    fn min_rest_breaches() {
        let cal = sun_thu();
        let week = vec![shift(3, 14, 22), shift(4, 6, 12)];
        let got = check(&week, &rules(), &ctx(&cal));
        let rest = got.iter().find(|b| b.code == "min_rest").expect("min_rest");
        assert_eq!(rest.shift_ids, vec![week[1].id]);
    }

    #[test]
    fn max_nights_passes() {
        let cal = sun_thu();
        let week = vec![shift(3, 22, 6), shift(5, 22, 6)];
        assert!(!codes(&week, &ctx(&cal)).contains(&"max_nights"));
    }

    #[test]
    fn max_nights_breaches() {
        let cal = sun_thu();
        let week = vec![shift(3, 22, 6), shift(5, 22, 6), shift(7, 22, 6)];
        assert!(codes(&week, &ctx(&cal)).contains(&"max_nights"));
    }

    #[test]
    fn days_off_passes() {
        let cal = sun_thu();
        assert!(!codes(&normal_week(), &ctx(&cal)).contains(&"days_off"));
    }

    #[test]
    fn days_off_breaches() {
        let cal = sun_thu();
        let mut week = normal_week();
        week.push(shift(8, 8, 14)); // Friday too: six days worked.
        assert!(codes(&week, &ctx(&cal)).contains(&"days_off"));
    }

    #[test]
    fn ramadan_passes() {
        let cal = sun_thu();
        let week: Vec<Shift> = (3..=7).map(|d| shift(d, 10, 16)).collect();
        let c = WeekContext {
            calendar: &cal,
            ramadan: Some((
                NaiveDate::from_ymd_opt(2027, 1, 1).expect("date"),
                NaiveDate::from_ymd_opt(2027, 1, 30).expect("date"),
            )),
            ramadan_pattern: true,
        };
        assert!(codes(&week, &c).is_empty());
    }

    #[test]
    fn ramadan_breaches() {
        let cal = sun_thu();
        let c = WeekContext {
            calendar: &cal,
            ramadan: Some((
                NaiveDate::from_ymd_opt(2027, 1, 1).expect("date"),
                NaiveDate::from_ymd_opt(2027, 1, 30).expect("date"),
            )),
            ramadan_pattern: true,
        };
        // Eight hours is fine on an ordinary day but over the Ramadan day.
        assert_eq!(codes(&normal_week(), &c), vec!["ramadan"; 5]);
        let off_pattern = WeekContext {
            ramadan_pattern: false,
            ..c
        };
        assert!(codes(&normal_week(), &off_pattern).is_empty());
    }

    #[test]
    fn saudi_sunday_thursday_week_days_off() {
        let saudi = sun_thu();
        assert_eq!(week_start(&saudi), Weekday::Sun);
        let mon_fri = calendar(&[
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
            Weekday::Fri,
        ]);
        assert_eq!(week_start(&mon_fri), Weekday::Mon);
        // Sunday to Thursday in a Saudi week leaves Friday and Saturday off.
        assert!(!codes(&normal_week(), &ctx(&saudi)).contains(&"days_off"));
    }
}
