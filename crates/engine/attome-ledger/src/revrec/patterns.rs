//! F11-T5: the recognition patterns of a revenue rule (`revenue_rule.pattern`),
//! as pure functions from an obligation's allocated amount and what has
//! happened to it, to amounts per fiscal period.
//!
//! - `point_in_time`: in full in the period of the F6 delivery or acceptance;
//!   nothing until one is known.
//! - `ratable`: evenly per day over the service dates (an F3 subscription
//!   segment, or the line's own period).
//! - `milestone`: each completed V1 milestone's share in the period it
//!   completed; once every milestone is complete the last takes the cent
//!   remainder so the whole amount is recognised.
//! - `usage`: each F3 rated usage amount in the period it was rated.
//! - `percent_complete`: allocated x (cost to date / estimated total cost),
//!   less what was already recognised, in the period of `as_of`; never
//!   negative, unless the estimate rose and the catch-up is a reversal.
//!
//! The caller gathers the inputs (deliveries, segments, milestones, usage,
//! project costs) and writes the schedule lines; nothing here reads or
//! writes the database.

use chrono::NaiveDate;
use rust_decimal::Decimal;

use super::schedule::{FiscalPeriod, point_in_time, ratable_daily};

/// A revenue rule's pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    PointInTime,
    Ratable,
    Milestone,
    Usage,
    PercentComplete,
}

impl Pattern {
    /// The stored choice; `None` for an unknown one.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "point_in_time" => Self::PointInTime,
            "ratable" => Self::Ratable,
            "milestone" => Self::Milestone,
            "usage" => Self::Usage,
            "percent_complete" => Self::PercentComplete,
            _ => return None,
        })
    }
}

/// One milestone: its share of the obligation (0 to 1) and when it was
/// completed, if it was.
#[derive(Debug, Clone, PartialEq)]
pub struct Milestone {
    pub share: Decimal,
    pub completed_on: Option<NaiveDate>,
}

/// What has happened to an obligation, as far as its pattern needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PatternInputs {
    /// The F6 delivery or acceptance date.
    pub delivered_on: Option<NaiveDate>,
    /// The service dates, first and last day.
    pub service: Option<(NaiveDate, NaiveDate)>,
    pub milestones: Vec<Milestone>,
    /// Rated usage: the day rated and its amount.
    pub usage: Vec<(NaiveDate, Decimal)>,
    pub cost_to_date: Option<Decimal>,
    pub estimated_total_cost: Option<Decimal>,
    /// What earlier schedule lines already recognised.
    pub recognised_to_date: Decimal,
    /// The day a percent-complete catch-up is recognised on.
    pub as_of: Option<NaiveDate>,
}

fn period_of(date: NaiveDate, periods: &[FiscalPeriod]) -> Result<&FiscalPeriod, String> {
    periods
        .iter()
        .find(|p| p.start <= date && p.end >= date)
        .ok_or_else(|| format!("no fiscal period contains {date}"))
}

/// Adds `amount` to `period` in `out`, keeping the first-seen order.
fn add(out: &mut Vec<(String, Decimal)>, period: &str, amount: Decimal) {
    match out.iter_mut().find(|(p, _)| p == period) {
        Some((_, total)) => *total += amount,
        None => out.push((period.to_owned(), amount)),
    }
}

/// The amounts `pattern` recognises for an obligation of `allocated`, per
/// fiscal period. An empty list means nothing is recognised yet.
pub fn schedule_for(
    pattern: Pattern,
    allocated: Decimal,
    inputs: &PatternInputs,
    periods: &[FiscalPeriod],
) -> Result<Vec<(String, Decimal)>, String> {
    match pattern {
        Pattern::PointInTime => match inputs.delivered_on {
            Some(date) => point_in_time(allocated, date, periods),
            None => Ok(Vec::new()),
        },
        Pattern::Ratable => {
            let (start, end) = inputs
                .service
                .ok_or("a ratable obligation needs its service dates")?;
            ratable_daily(allocated, start, end, periods)
        }
        Pattern::Milestone => milestone(allocated, &inputs.milestones, periods),
        Pattern::Usage => {
            let mut out = Vec::new();
            for (date, amount) in &inputs.usage {
                add(&mut out, &period_of(*date, periods)?.name, *amount);
            }
            Ok(out)
        }
        Pattern::PercentComplete => percent_complete(allocated, inputs, periods),
    }
}

fn milestone(
    allocated: Decimal,
    milestones: &[Milestone],
    periods: &[FiscalPeriod],
) -> Result<Vec<(String, Decimal)>, String> {
    let total_share: Decimal = milestones.iter().map(|m| m.share).sum();
    if milestones.iter().any(|m| m.share < Decimal::ZERO) || total_share > Decimal::ONE {
        return Err("milestone shares are between 0 and 1 and add up to at most 1".into());
    }
    let all_done = !milestones.is_empty()
        && milestones.iter().all(|m| m.completed_on.is_some())
        && total_share == Decimal::ONE;
    let mut done: Vec<&Milestone> = milestones
        .iter()
        .filter(|m| m.completed_on.is_some())
        .collect();
    done.sort_by_key(|m| m.completed_on);
    let mut out = Vec::new();
    let mut assigned = Decimal::ZERO;
    let last = done.len().saturating_sub(1);
    for (i, m) in done.iter().enumerate() {
        let Some(date) = m.completed_on else {
            continue;
        };
        let amount = if all_done && i == last {
            allocated - assigned
        } else {
            (allocated * m.share).round_dp(2)
        };
        assigned += amount;
        add(&mut out, &period_of(date, periods)?.name, amount);
    }
    Ok(out)
}

fn percent_complete(
    allocated: Decimal,
    inputs: &PatternInputs,
    periods: &[FiscalPeriod],
) -> Result<Vec<(String, Decimal)>, String> {
    let estimate = inputs
        .estimated_total_cost
        .filter(|e| *e > Decimal::ZERO)
        .ok_or("percent complete needs an estimated total cost above zero")?;
    let cost = inputs
        .cost_to_date
        .unwrap_or(Decimal::ZERO)
        .max(Decimal::ZERO);
    let as_of = inputs
        .as_of
        .ok_or("percent complete needs the day to recognise on")?;
    let progress = (cost / estimate).min(Decimal::ONE);
    let earned = (allocated * progress).round_dp(2);
    let catch_up = earned - inputs.recognised_to_date;
    // A negative catch-up is a reversal: allowed only when the estimate rose
    // (progress fell); it never takes back more than was recognised.
    let catch_up = catch_up.max(-inputs.recognised_to_date);
    if catch_up == Decimal::ZERO {
        return Ok(Vec::new());
    }
    Ok(vec![(period_of(as_of, periods)?.name.clone(), catch_up)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn months() -> Vec<FiscalPeriod> {
        ["01", "02", "03"]
            .iter()
            .map(|m| {
                let start = d(&format!("2026-{m}-01"));
                let end = match *m {
                    "01" => d("2026-01-31"),
                    "02" => d("2026-02-28"),
                    _ => d("2026-03-31"),
                };
                FiscalPeriod {
                    name: format!("2026-{m}"),
                    start,
                    end,
                }
            })
            .collect()
    }

    #[test]
    fn milestone_share_on_completion() {
        let inputs = PatternInputs {
            milestones: vec![
                Milestone {
                    share: dec("0.3"),
                    completed_on: Some(d("2026-01-15")),
                },
                Milestone {
                    share: dec("0.3"),
                    completed_on: Some(d("2026-02-10")),
                },
                Milestone {
                    share: dec("0.4"),
                    completed_on: None,
                },
            ],
            ..PatternInputs::default()
        };
        let out = schedule_for(Pattern::Milestone, dec("1000.00"), &inputs, &months()).unwrap();
        assert_eq!(
            out,
            vec![
                ("2026-01".into(), dec("300.00")),
                ("2026-02".into(), dec("300.00"))
            ]
        );
        // All three done: the last takes the remainder so the whole is recognised.
        let mut all = inputs.clone();
        all.milestones[2].completed_on = Some(d("2026-03-05"));
        let out = schedule_for(Pattern::Milestone, dec("100.01"), &all, &months()).unwrap();
        let total: Decimal = out.iter().map(|(_, a)| *a).sum();
        assert_eq!(total, dec("100.01"));
    }

    #[test]
    fn percent_complete_catches_up() {
        let mut inputs = PatternInputs {
            cost_to_date: Some(dec("250")),
            estimated_total_cost: Some(dec("1000")),
            recognised_to_date: dec("0"),
            as_of: Some(d("2026-01-31")),
            ..PatternInputs::default()
        };
        let out = schedule_for(Pattern::PercentComplete, dec("2000"), &inputs, &months()).unwrap();
        assert_eq!(out, vec![("2026-01".into(), dec("500.00"))]);
        // Next month, 60% done: only the catch-up beyond what was recognised.
        inputs.cost_to_date = Some(dec("600"));
        inputs.recognised_to_date = dec("500.00");
        inputs.as_of = Some(d("2026-02-28"));
        let out = schedule_for(Pattern::PercentComplete, dec("2000"), &inputs, &months()).unwrap();
        assert_eq!(out, vec![("2026-02".into(), dec("700.00"))]);
        // The estimate rises to 2000: progress falls to 30%, a reversal.
        inputs.estimated_total_cost = Some(dec("2000"));
        inputs.recognised_to_date = dec("1200.00");
        inputs.as_of = Some(d("2026-03-31"));
        let out = schedule_for(Pattern::PercentComplete, dec("2000"), &inputs, &months()).unwrap();
        assert_eq!(out, vec![("2026-03".into(), dec("-600.00"))]);
        // Without an estimate it refuses.
        inputs.estimated_total_cost = None;
        assert!(schedule_for(Pattern::PercentComplete, dec("2000"), &inputs, &months()).is_err());
    }

    #[test]
    fn usage_in_rated_period() {
        let inputs = PatternInputs {
            usage: vec![
                (d("2026-01-10"), dec("12.50")),
                (d("2026-01-20"), dec("7.50")),
                (d("2026-03-01"), dec("4.00")),
            ],
            ..PatternInputs::default()
        };
        let out = schedule_for(Pattern::Usage, dec("0"), &inputs, &months()).unwrap();
        assert_eq!(
            out,
            vec![
                ("2026-01".into(), dec("20.00")),
                ("2026-03".into(), dec("4.00"))
            ]
        );
    }

    #[test]
    fn point_in_time_waits_for_delivery_and_ratable_needs_dates() {
        let none = PatternInputs::default();
        assert!(
            schedule_for(Pattern::PointInTime, dec("10"), &none, &months())
                .unwrap()
                .is_empty()
        );
        let delivered = PatternInputs {
            delivered_on: Some(d("2026-02-02")),
            ..PatternInputs::default()
        };
        assert_eq!(
            schedule_for(Pattern::PointInTime, dec("10"), &delivered, &months()).unwrap(),
            vec![("2026-02".into(), dec("10"))]
        );
        assert!(schedule_for(Pattern::Ratable, dec("10"), &none, &months()).is_err());
        assert_eq!(Pattern::parse("usage"), Some(Pattern::Usage));
        assert_eq!(Pattern::parse("weekly"), None);
    }
}
