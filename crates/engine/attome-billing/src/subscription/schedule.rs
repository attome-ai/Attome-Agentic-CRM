//! Billing schedule and proration (roadmap F3-T4): the periods a
//! subscription bills, in advance or in arrears, monthly, quarterly or
//! yearly, aligned to the start date's anniversary or to calendar months,
//! with a part period prorated by days.

use chrono::{Datelike, Months, NaiveDate};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// One billing period, `end` exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Period {
    pub start: NaiveDate,
    pub end: NaiveDate,
    pub bill_on: NaiveDate,
    /// The share of a full period this one is (1 for a full period).
    pub prorate_factor: Decimal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    Monthly,
    Quarterly,
    Yearly,
}

impl Cadence {
    fn months(self) -> u32 {
        match self {
            Self::Monthly => 1,
            Self::Quarterly => 3,
            Self::Yearly => 12,
        }
    }
}

/// How often to bill, and on which calendar. Billing on Hijri months is an
/// open point and stays off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frequency {
    pub cadence: Cadence,
    #[serde(default)]
    pub hijri: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alignment {
    /// Periods start on the start date's day of the month.
    Anniversary,
    /// Periods start on the first of a month, quarter or year.
    CalendarMonth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Timing {
    /// Billed when the period starts.
    Advance,
    /// Billed when the period ends.
    Arrears,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    #[error("billing on Hijri months is not available yet")]
    HijriUnavailable,
    #[error("the subscription ends before it starts")]
    EndBeforeStart,
}

/// The most periods one call produces.
const MAX_PERIODS: usize = 10_000;

/// `date` plus `months`, on `day` of that month or its last day.
fn add_months_on_day(date: NaiveDate, months: u32, day: u32) -> Option<NaiveDate> {
    let first = date.with_day(1)?.checked_add_months(Months::new(months))?;
    let last = first.checked_add_months(Months::new(1))?.pred_opt()?.day();
    first.with_day(day.min(last))
}

/// The first calendar boundary (first of a month, quarter or year) after
/// `date`.
fn next_boundary(date: NaiveDate, cadence: Cadence) -> Option<NaiveDate> {
    let step = cadence.months();
    // Months since the start of the year, rounded down to the cadence.
    let month0 = date.month0() / step * step;
    let start = NaiveDate::from_ymd_opt(date.year(), month0 + 1, 1)?;
    start.checked_add_months(Months::new(step))
}

fn days(from: NaiveDate, to: NaiveDate) -> i64 {
    (to - from).num_days()
}

fn factor(part: i64, whole: i64) -> Decimal {
    if whole <= 0 || part >= whole {
        Decimal::ONE
    } else {
        Decimal::from(part.max(0)) / Decimal::from(whole)
    }
}

/// Every period that starts before `horizon`, from `start` to `end`
/// (exclusive; `None` runs on).
pub fn periods(
    start: NaiveDate,
    end: Option<NaiveDate>,
    freq: Frequency,
    alignment: Alignment,
    timing: Timing,
    horizon: NaiveDate,
) -> Result<Vec<Period>, ScheduleError> {
    if freq.hijri {
        return Err(ScheduleError::HijriUnavailable);
    }
    if end.is_some_and(|e| e <= start) {
        return Err(ScheduleError::EndBeforeStart);
    }
    let step = freq.cadence.months();
    let mut out = Vec::new();
    let mut period_start = start;
    let mut k: u32 = 0;
    while period_start < horizon && end.is_none_or(|e| period_start < e) && out.len() < MAX_PERIODS
    {
        // The full period this one belongs to, and where it ends.
        let (full_start, full_end) = match alignment {
            Alignment::Anniversary => {
                let Some(next) = add_months_on_day(start, step * (k + 1), start.day()) else {
                    break;
                };
                (period_start, next)
            }
            Alignment::CalendarMonth => {
                let Some(next) = next_boundary(period_start, freq.cadence) else {
                    break;
                };
                let Some(full_start) = next.checked_sub_months(Months::new(step)) else {
                    break;
                };
                (full_start, next)
            }
        };
        let period_end = end.map_or(full_end, |e| e.min(full_end));
        let prorate_factor = factor(days(period_start, period_end), days(full_start, full_end));
        out.push(Period {
            start: period_start,
            end: period_end,
            bill_on: match timing {
                Timing::Advance => period_start,
                Timing::Arrears => period_end,
            },
            prorate_factor,
        });
        period_start = period_end;
        k += 1;
    }
    Ok(out)
}

/// The share of `period` left from `effective` on: what a mid-period change
/// charges or credits.
pub fn proration_for_change(period: &Period, effective: NaiveDate) -> Decimal {
    if effective <= period.start {
        return Decimal::ONE;
    }
    if effective >= period.end {
        return Decimal::ZERO;
    }
    factor(days(effective, period.end), days(period.start, period.end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    fn freq(cadence: Cadence) -> Frequency {
        Frequency {
            cadence,
            hijri: false,
        }
    }

    #[test]
    fn monthly_anniversary_clamps_31st() {
        let p = periods(
            d(2027, 1, 31),
            None,
            freq(Cadence::Monthly),
            Alignment::Anniversary,
            Timing::Advance,
            d(2027, 5, 1),
        )
        .expect("periods");
        let starts: Vec<NaiveDate> = p.iter().map(|p| p.start).collect();
        assert_eq!(
            starts,
            vec![
                d(2027, 1, 31),
                d(2027, 2, 28),
                d(2027, 3, 31),
                d(2027, 4, 30)
            ]
        );
        assert!(p.iter().all(|p| p.prorate_factor == Decimal::ONE));
    }

    #[test]
    fn calendar_alignment_prorates_first_period() {
        let p = periods(
            d(2027, 3, 15),
            None,
            freq(Cadence::Yearly),
            Alignment::CalendarMonth,
            Timing::Advance,
            d(2028, 6, 1),
        )
        .expect("periods");
        assert_eq!(p[0].end, d(2028, 1, 1));
        assert_eq!(p[0].prorate_factor, Decimal::from(292) / Decimal::from(365));
        assert_eq!(p[1].start, d(2028, 1, 1));
        assert_eq!(p[1].prorate_factor, Decimal::ONE);

        let monthly = periods(
            d(2027, 4, 11),
            Some(d(2027, 6, 21)),
            freq(Cadence::Monthly),
            Alignment::CalendarMonth,
            Timing::Advance,
            d(2028, 1, 1),
        )
        .expect("periods");
        assert_eq!(monthly.len(), 3);
        assert_eq!(
            monthly[0].prorate_factor,
            Decimal::from(20) / Decimal::from(30)
        );
        assert_eq!(
            monthly[2].end,
            d(2027, 6, 21),
            "the last period stops at the end"
        );
        assert_eq!(
            monthly[2].prorate_factor,
            Decimal::from(20) / Decimal::from(30)
        );
    }

    #[test]
    fn arrears_bills_at_period_end() {
        let p = periods(
            d(2027, 1, 1),
            None,
            freq(Cadence::Quarterly),
            Alignment::CalendarMonth,
            Timing::Arrears,
            d(2027, 7, 1),
        )
        .expect("periods");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].bill_on, d(2027, 4, 1));
        assert_eq!(p[1].bill_on, d(2027, 7, 1));
        assert_eq!(
            periods(
                d(2027, 1, 1),
                None,
                Frequency {
                    cadence: Cadence::Monthly,
                    hijri: true
                },
                Alignment::Anniversary,
                Timing::Advance,
                d(2028, 1, 1),
            ),
            Err(ScheduleError::HijriUnavailable)
        );
    }

    #[test]
    fn change_mid_period_prorates() {
        let period = Period {
            start: d(2027, 4, 1),
            end: d(2027, 5, 1),
            bill_on: d(2027, 4, 1),
            prorate_factor: Decimal::ONE,
        };
        assert_eq!(
            proration_for_change(&period, d(2027, 4, 16)),
            Decimal::from(15) / Decimal::from(30)
        );
        assert_eq!(proration_for_change(&period, d(2027, 3, 1)), Decimal::ONE);
        assert_eq!(proration_for_change(&period, d(2027, 5, 1)), Decimal::ZERO);
    }
}
