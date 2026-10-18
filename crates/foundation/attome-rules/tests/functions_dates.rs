//! Z11-T4: Hijri dates, zones and working days, the calendar coming from the
//! Context.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashSet;
use std::sync::Arc;

use attome_calendar::{BusinessCalendar, TimeRange};
use attome_rules::{
    Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value, compile_versioned,
};
use chrono::{DateTime, TimeZone, Utc, Weekday};

fn at(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap()
}

fn sun_thu() -> Arc<BusinessCalendar> {
    let days: HashSet<Weekday> = [
        Weekday::Sun,
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
    ]
    .into_iter()
    .collect();
    Arc::new(
        BusinessCalendar::simple(
            chrono_tz::Asia::Riyadh,
            days,
            TimeRange::new(8 * 60, 16 * 60),
        )
        .unwrap(),
    )
}

fn run(src: &str, ctx: &Context) -> Result<Value, RulesError> {
    let schema = Schema::new()
        .with_field("due", Type::Date)
        .with_field("start", Type::Date);
    compile_versioned(src, &schema, LanguageVersion::V2, Budgets::default())?.eval(ctx)
}

fn ctx(due: DateTime<Utc>) -> Context {
    Context::new(Utc::now())
        .with_timezone_name("Asia/Riyadh")
        .unwrap()
        .with_field("due", Value::Date(due))
        .with_field("start", Value::Date(due))
}

#[test]
fn hijri_month_of_known_date() {
    // 1 March 2025, 09:00 in Riyadh, is 1 Ramadan 1446.
    let c = ctx(at(2025, 3, 1, 6));
    assert_eq!(run("hijri_month(due)", &c).unwrap(), Value::Number(9.0));
    assert_eq!(run("hijri_year(due)", &c).unwrap(), Value::Number(1446.0));
    assert_eq!(run("hijri_day(due)", &c).unwrap(), Value::Number(1.0));
    // 1 Shawwal 1446 begins at Riyadh midnight, 2025-03-29 21:00 UTC.
    assert_eq!(
        run("hijri_date(1446, 10, 1)", &c).unwrap(),
        Value::Date(at(2025, 3, 29, 21))
    );
    assert_eq!(
        run("to_zone(due, \"Asia/Dubai\") == due", &c).unwrap(),
        Value::Bool(true)
    );
    let bad = run("to_zone(due, \"Mars/Base\")", &c).unwrap_err();
    assert_eq!(bad.code(), "rules.context.unknown_timezone");
}

#[test]
fn add_workdays_skips_friday_saturday() {
    // Thursday 2026-08-27, 10:00 Riyadh.
    let c = ctx(at(2026, 8, 27, 7)).with_calendar(sun_thu());
    assert_eq!(
        run("add_workdays(due, 1)", &c).unwrap(),
        Value::Date(at(2026, 8, 30, 7)),
        "Thursday plus one working day is Sunday"
    );
    assert_eq!(
        run("add_workdays(due, -4)", &c).unwrap(),
        Value::Date(at(2026, 8, 23, 7)),
        "back four working days is the Sunday before"
    );
    assert_eq!(run("is_working(due)", &c).unwrap(), Value::Bool(true));
    let friday = ctx(at(2026, 8, 28, 7)).with_calendar(sun_thu());
    assert_eq!(run("is_working(due)", &friday).unwrap(), Value::Bool(false));
    assert_eq!(
        run("workdays_between(due, add_workdays(due, 3))", &c).unwrap(),
        Value::Number(3.0)
    );
}

#[test]
fn workday_function_without_calendar_errors() {
    let c = ctx(at(2026, 8, 27, 7));
    for src in [
        "add_workdays(due, 1)",
        "workdays_between(due, start)",
        "is_working(due)",
    ] {
        let err = run(src, &c).unwrap_err();
        assert_eq!(err.code(), "rules.calendar.missing", "{src}");
    }
}

#[test]
fn hijri_out_of_range_errors() {
    let c = ctx(at(1900, 1, 1, 12));
    assert_eq!(
        run("hijri_year(due)", &c).unwrap_err().code(),
        "rules.hijri.out_of_range"
    );
    assert_eq!(
        run("hijri_date(1600, 1, 1)", &c).unwrap_err().code(),
        "rules.hijri.out_of_range"
    );
    // The functions are V2.
    let v1 = compile_versioned(
        "hijri_year(due)",
        &Schema::new().with_field("due", Type::Date),
        LanguageVersion::V1,
        Budgets::default(),
    );
    assert!(matches!(v1, Err(RulesError::UnknownFunction(_))));
}
