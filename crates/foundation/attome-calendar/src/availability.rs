//! Free slots (roadmap D20-T1), pure: the times a meeting of a given length
//! fits for everyone, inside every attendee's working hours (their own
//! calendar: working days, hours, holidays and exceptions, in its own time
//! zone) and outside everything they are busy with, keeping a buffer around
//! each busy interval.

use chrono::{DateTime, Duration, Utc};

use crate::{BusinessCalendar, CalendarError, IntervalWalk};

/// A half-open interval `[start, end)` in UTC.
pub type Interval = (DateTime<Utc>, DateTime<Utc>);

/// What to look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotRequest {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// How long the meeting is.
    pub duration: Duration,
    /// Free time kept before and after each busy interval.
    pub buffer: Duration,
    /// How far apart offered start times are (e.g. 15 or 30 minutes).
    pub step: Duration,
    /// The most slots to return.
    pub limit: usize,
}

/// The working intervals of `calendar` within `[from, to)`.
fn working(
    calendar: &BusinessCalendar,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<Interval>, CalendarError> {
    IntervalWalk::new(calendar, from, to).collect()
}

/// The overlap of two sorted, non-overlapping interval lists.
fn intersect(a: &[Interval], b: &[Interval]) -> Vec<Interval> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        let start = a[i].0.max(b[j].0);
        let end = a[i].1.min(b[j].1);
        if start < end {
            out.push((start, end));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// `free` minus every busy interval widened by `buffer` on both sides.
fn subtract(free: &[Interval], busy: &[Interval], buffer: Duration) -> Vec<Interval> {
    let mut blocked: Vec<Interval> = busy
        .iter()
        .filter(|(s, e)| s < e)
        .map(|(s, e)| (*s - buffer, *e + buffer))
        .collect();
    blocked.sort();
    let mut out = Vec::new();
    for &(start, end) in free {
        let mut cursor = start;
        for &(b_start, b_end) in &blocked {
            if b_end <= cursor || b_start >= end {
                continue;
            }
            if b_start > cursor {
                out.push((cursor, b_start));
            }
            cursor = cursor.max(b_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            out.push((cursor, end));
        }
    }
    out
}

/// Start times, `step` apart from each free interval's start, where a
/// meeting of `request.duration` fits for every attendee. Each attendee is
/// a calendar and their busy intervals.
pub fn free_slots(
    attendees: &[(&BusinessCalendar, &[Interval])],
    request: &SlotRequest,
) -> Result<Vec<Interval>, CalendarError> {
    if request.from >= request.to
        || request.duration <= Duration::zero()
        || request.step <= Duration::zero()
    {
        return Ok(Vec::new());
    }
    let mut common: Option<Vec<Interval>> = None;
    for (calendar, busy) in attendees {
        let mine = subtract(
            &working(calendar, request.from, request.to)?,
            busy,
            request.buffer,
        );
        common = Some(match common {
            None => mine,
            Some(so_far) => intersect(&so_far, &mine),
        });
    }
    let mut slots = Vec::new();
    for (start, end) in common.unwrap_or_default() {
        let mut at = start;
        while at + request.duration <= end {
            slots.push((at, at + request.duration));
            if slots.len() >= request.limit {
                return Ok(slots);
            }
            at += request.step;
        }
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimeRange;
    use crate::hijri::{HijriDate, from_hijri};
    use chrono::{NaiveDate, TimeZone, Weekday};
    use chrono_tz::Tz;
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    fn riyadh() -> Tz {
        "Asia/Riyadh".parse().expect("zone")
    }

    /// Sun-Thu 09:00-17:00 Riyadh time, the Gulf working week.
    fn gulf(holidays: &[NaiveDate]) -> BusinessCalendar {
        let days: HashSet<Weekday> = [
            Weekday::Sun,
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
        ]
        .into_iter()
        .collect();
        let hours: HashMap<Weekday, Vec<TimeRange>> = days
            .iter()
            .map(|d| (*d, vec![TimeRange::new(9 * 60, 17 * 60)]))
            .collect();
        BusinessCalendar::new(
            riyadh(),
            days,
            hours,
            holidays.iter().copied().collect::<BTreeSet<_>>(),
            BTreeMap::new(),
        )
        .expect("calendar")
    }

    fn local(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        riyadh()
            .with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("time")
            .with_timezone(&Utc)
    }

    fn request(from: DateTime<Utc>, to: DateTime<Utc>) -> SlotRequest {
        SlotRequest {
            from,
            to,
            duration: Duration::minutes(60),
            buffer: Duration::minutes(15),
            step: Duration::minutes(30),
            limit: 100,
        }
    }

    #[test]
    fn slots_fall_in_hours_around_busy_time_with_buffers() {
        let cal = gulf(&[]);
        // Sunday 2027-01-03, busy 11:00-12:00.
        let busy = [(local(2027, 1, 3, 11, 0), local(2027, 1, 3, 12, 0))];
        let slots = free_slots(
            &[(&cal, &busy)],
            &request(local(2027, 1, 3, 0, 0), local(2027, 1, 4, 0, 0)),
        )
        .expect("slots");
        let starts: Vec<DateTime<Utc>> = slots.iter().map(|s| s.0).collect();
        // 09:00, 09:30 end by 10:45; 12:15 onward until 16:00.
        assert_eq!(starts[0], local(2027, 1, 3, 9, 0));
        assert_eq!(starts[1], local(2027, 1, 3, 9, 30));
        assert_eq!(starts[2], local(2027, 1, 3, 12, 15));
        assert_eq!(*starts.last().expect("a slot"), local(2027, 1, 3, 15, 45));
        assert!(slots.iter().all(|(s, e)| *e - *s == Duration::minutes(60)));
    }

    #[test]
    fn gulf_weekend_has_no_slots() {
        let cal = gulf(&[]);
        // Friday and Saturday 2027-01-08/09.
        let slots = free_slots(
            &[(&cal, &[])],
            &request(local(2027, 1, 8, 0, 0), local(2027, 1, 10, 0, 0)),
        )
        .expect("slots");
        assert!(slots.is_empty());
    }

    #[test]
    fn a_hijri_holiday_has_no_slots() {
        // 1 Shawwal 1448 (Eid al-Fitr) as a holiday.
        let eid = from_hijri(HijriDate::new(1448, 10, 1)).expect("in range");
        let cal = gulf(&[eid]);
        let start = riyadh()
            .from_local_datetime(&eid.and_hms_opt(0, 0, 0).expect("midnight"))
            .single()
            .expect("time")
            .with_timezone(&Utc);
        let slots =
            free_slots(&[(&cal, &[])], &request(start, start + Duration::days(1))).expect("slots");
        assert!(slots.is_empty(), "no meetings on Eid");
    }

    #[test]
    fn two_attendees_share_only_common_time() {
        let cal = gulf(&[]);
        let first_busy = [(local(2027, 1, 3, 9, 0), local(2027, 1, 3, 13, 0))];
        let second_busy = [(local(2027, 1, 3, 14, 0), local(2027, 1, 3, 17, 0))];
        let slots = free_slots(
            &[(&cal, &first_busy), (&cal, &second_busy)],
            &request(local(2027, 1, 3, 0, 0), local(2027, 1, 4, 0, 0)),
        )
        .expect("slots");
        // Only 13:15-13:45 is free for both, too short for an hour.
        assert!(slots.is_empty());
        let mut short = request(local(2027, 1, 3, 0, 0), local(2027, 1, 4, 0, 0));
        short.duration = Duration::minutes(30);
        let slots =
            free_slots(&[(&cal, &first_busy), (&cal, &second_busy)], &short).expect("slots");
        assert_eq!(
            slots,
            vec![(local(2027, 1, 3, 13, 15), local(2027, 1, 3, 13, 45))]
        );
    }
}
