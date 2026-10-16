//! Recurrence rules for things that repeat on dates (obligations, tasks):
//! `daily`, `weekly`, `monthly`, `quarterly`, `yearly` (or `annually`), or
//! an iCalendar `FREQ=…;INTERVAL=n` rule, and the next date after one.

use chrono::{Months, NaiveDate};

/// How often something repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recurrence {
    Daily(u32),
    Weekly(u32),
    Monthly(u32),
    Yearly(u32),
}

/// Reads a recurrence rule: `daily`, `weekly`, `monthly`, `quarterly`,
/// `yearly` (or `annually`), or an iCalendar `FREQ=…;INTERVAL=n` rule.
/// `None` for anything else.
pub fn parse_recurrence(rule: &str) -> Option<Recurrence> {
    let rule = rule
        .trim()
        .trim_start_matches("RRULE:")
        .to_ascii_uppercase();
    match rule.as_str() {
        "DAILY" => return Some(Recurrence::Daily(1)),
        "WEEKLY" => return Some(Recurrence::Weekly(1)),
        "MONTHLY" => return Some(Recurrence::Monthly(1)),
        "QUARTERLY" => return Some(Recurrence::Monthly(3)),
        "YEARLY" | "ANNUALLY" => return Some(Recurrence::Yearly(1)),
        _ => {}
    }
    let mut freq = None;
    let mut interval = 1u32;
    for part in rule.split(';') {
        let (key, value) = part.split_once('=')?;
        match key.trim() {
            "FREQ" => freq = Some(value.trim().to_owned()),
            "INTERVAL" => interval = value.trim().parse().ok().filter(|n| *n > 0)?,
            _ => {}
        }
    }
    match freq.as_deref()? {
        "DAILY" => Some(Recurrence::Daily(interval)),
        "WEEKLY" => Some(Recurrence::Weekly(interval)),
        "MONTHLY" => Some(Recurrence::Monthly(interval)),
        "YEARLY" => Some(Recurrence::Yearly(interval)),
        _ => None,
    }
}

/// The next occurrence after `after`. A monthly rule keeps to the month's
/// last day when the day does not exist (31 January, then 28 or 29
/// February).
pub fn next_occurrence(rule: Recurrence, after: NaiveDate) -> Option<NaiveDate> {
    match rule {
        Recurrence::Daily(n) => after.checked_add_signed(chrono::Duration::days(i64::from(n))),
        Recurrence::Weekly(n) => after.checked_add_signed(chrono::Duration::weeks(i64::from(n))),
        Recurrence::Monthly(n) => after.checked_add_months(Months::new(n)),
        Recurrence::Yearly(n) => after.checked_add_months(Months::new(n.checked_mul(12)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap_or_default()
    }

    #[test]
    fn monthly_recurrence_end_of_month() {
        let monthly = parse_recurrence("monthly");
        assert_eq!(monthly, Some(Recurrence::Monthly(1)));
        let next = monthly.and_then(|r| next_occurrence(r, day(2026, 1, 31)));
        assert_eq!(next, Some(day(2026, 2, 28)));
        let leap = monthly.and_then(|r| next_occurrence(r, day(2028, 1, 31)));
        assert_eq!(leap, Some(day(2028, 2, 29)));
        assert_eq!(
            parse_recurrence("RRULE:FREQ=MONTHLY;INTERVAL=3")
                .and_then(|r| next_occurrence(r, day(2026, 11, 30))),
            Some(day(2027, 2, 28))
        );
        assert_eq!(parse_recurrence("quarterly"), Some(Recurrence::Monthly(3)));
        assert_eq!(parse_recurrence("FREQ=HOURLY"), None);
        assert_eq!(parse_recurrence("FREQ=WEEKLY;INTERVAL=0"), None);
        assert_eq!(parse_recurrence("sometimes"), None);
    }
}
