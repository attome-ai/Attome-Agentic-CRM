//! Calling hours (roadmap D21-T4), pure: whether a number may be called
//! now, from the `calling_hours` rows (country, ISO weekday 1 = Monday to
//! 7 = Sunday, local start and end `HH:MM`). A country with no rule may not
//! be called; the `*` country is the default for countries without their
//! own rows. The country comes from the number's dialling code.

use chrono::{DateTime, Datelike, NaiveTime, Utc};
use chrono_tz::Tz;

/// One calling-hours row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingHours {
    pub country: String,
    /// ISO weekday, 1 = Monday.
    pub weekday: u32,
    pub start: NaiveTime,
    pub end: NaiveTime,
}

impl CallingHours {
    /// Reads a stored row; `None` when a time is not `HH:MM` or the weekday
    /// is out of range.
    pub fn parse(country: &str, weekday: f64, start: &str, end: &str) -> Option<Self> {
        let day = weekday as u32;
        if !(1..=7).contains(&day) {
            return None;
        }
        Some(Self {
            country: country.trim().to_ascii_uppercase(),
            weekday: day,
            start: NaiveTime::parse_from_str(start.trim(), "%H:%M").ok()?,
            end: NaiveTime::parse_from_str(end.trim(), "%H:%M").ok()?,
        })
    }
}

/// Whether `now_utc` is inside a window for `country` in time zone `tz`.
pub fn within_calling_hours(
    rules: &[CallingHours],
    country: &str,
    now_utc: DateTime<Utc>,
    tz: Tz,
) -> bool {
    let country = country.trim().to_ascii_uppercase();
    let own: Vec<&CallingHours> = rules.iter().filter(|r| r.country == country).collect();
    let applicable: Vec<&CallingHours> = if own.is_empty() {
        rules.iter().filter(|r| r.country == "*").collect()
    } else {
        own
    };
    let local = now_utc.with_timezone(&tz);
    let weekday = local.weekday().number_from_monday();
    let time = local.time();
    applicable
        .iter()
        .any(|r| r.weekday == weekday && r.start <= time && time < r.end)
}

/// The country (ISO 3166 alpha-2) and time zone of an international number,
/// for the dialling codes this platform's regions use; `None` otherwise.
pub fn country_of(phone: &str) -> Option<(&'static str, Tz)> {
    let digits: String = phone
        .trim()
        .trim_start_matches('+')
        .trim_start_matches("00")
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    const CODES: &[(&str, &str, Tz)] = &[
        ("966", "SA", chrono_tz::Asia::Riyadh),
        ("971", "AE", chrono_tz::Asia::Dubai),
        ("965", "KW", chrono_tz::Asia::Kuwait),
        ("973", "BH", chrono_tz::Asia::Bahrain),
        ("968", "OM", chrono_tz::Asia::Muscat),
        ("974", "QA", chrono_tz::Asia::Qatar),
        ("962", "JO", chrono_tz::Asia::Amman),
        ("20", "EG", chrono_tz::Africa::Cairo),
        ("44", "GB", chrono_tz::Europe::London),
        ("1", "US", chrono_tz::America::New_York),
    ];
    CODES
        .iter()
        .find(|(code, _, _)| digits.starts_with(code))
        .map(|(_, country, tz)| (*country, *tz))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn rules() -> Vec<CallingHours> {
        // Sunday to Thursday, 09:00 to 18:00 in Saudi Arabia.
        (0..5)
            .filter_map(|i| {
                CallingHours::parse("sa", f64::from([7, 1, 2, 3, 4][i]), "09:00", "18:00")
            })
            .collect()
    }

    fn utc(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn blocks_before_start() {
        // Tuesday 3 November 2026, 05:00 UTC is 08:00 in Riyadh.
        assert!(!within_calling_hours(
            &rules(),
            "SA",
            utc(3, 5),
            chrono_tz::Asia::Riyadh
        ));
    }

    #[test]
    fn allows_inside_window() {
        assert!(within_calling_hours(
            &rules(),
            "SA",
            utc(3, 6),
            chrono_tz::Asia::Riyadh
        ));
        // Friday 6 November is not a calling day.
        assert!(!within_calling_hours(
            &rules(),
            "SA",
            utc(6, 8),
            chrono_tz::Asia::Riyadh
        ));
    }

    #[test]
    fn no_rule_means_blocked() {
        assert!(!within_calling_hours(
            &rules(),
            "AE",
            utc(3, 8),
            chrono_tz::Asia::Dubai
        ));
        let mut with_default = rules();
        with_default.extend(CallingHours::parse("*", 2.0, "08:00", "20:00"));
        assert!(within_calling_hours(
            &with_default,
            "AE",
            utc(3, 8),
            chrono_tz::Asia::Dubai
        ));
    }

    #[test]
    fn dialling_codes_give_the_country() {
        assert_eq!(country_of("+966 50 123 4567").map(|c| c.0), Some("SA"));
        assert_eq!(country_of("00971501234567").map(|c| c.0), Some("AE"));
        assert_eq!(country_of("050 123 4567"), None);
    }
}
