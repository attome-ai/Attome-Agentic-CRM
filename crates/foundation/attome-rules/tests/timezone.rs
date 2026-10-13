//! BRU-C4 — time-zone-aware dates (D-399 ruling 4 as amended by BRU-D4).
//!
//! Context carries the caller's IANA zone, UTC by default, so a caller that
//! sets nothing is unchanged. These tests pin the three cases the plan asks
//! for: a UTC+03 zone, a half-hour offset, and a DST-transition zone (plus the
//! unknown-zone error path and the local-calendar month difference).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{Context, RulesError, Schema, Type, Value, compile};
use chrono::{TimeZone, Utc};
use chrono_tz::{America, Asia};

fn date(y: i32, m: u32, d: u32, h: u32, min: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
}

#[test]
fn today_is_local_midnight_in_a_utc_plus_three_zone() {
    let compiled = compile("today()", &Schema::new()).unwrap();
    // 2026-09-22T22:30Z is 2026-09-23T01:30 in Riyadh (+03), so local midnight
    // is 2026-09-23T00:00+03 == 2026-09-22T21:00Z (the plan's own example).
    let ctx = Context::new(date(2026, 9, 22, 22, 30)).with_timezone(Asia::Riyadh);
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 9, 22, 21, 0))
    );
}

#[test]
fn today_uses_a_half_hour_offset() {
    let compiled = compile("today()", &Schema::new()).unwrap();
    // Kolkata is +05:30: 2026-09-22T22:30Z is local 2026-09-23T04:00, so local
    // midnight is 2026-09-22T18:30Z.
    let ctx = Context::new(date(2026, 9, 22, 22, 30)).with_timezone(Asia::Kolkata);
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 9, 22, 18, 30))
    );
}

#[test]
fn today_on_a_dst_transition_day_is_that_local_day() {
    let compiled = compile("today()", &Schema::new()).unwrap();
    // 2026-03-08 is the US spring-forward day (02:00 -> 03:00). 06:00Z is
    // 01:00 EST, still the 8th, so today() is 2026-03-08T00:00-05:00 == 05:00Z.
    let ctx = Context::new(date(2026, 3, 8, 6, 0)).with_timezone(America::New_York);
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 3, 8, 5, 0))
    );
}

#[test]
fn utc_is_the_default_and_does_not_change_behaviour() {
    let compiled = compile("today()", &Schema::new()).unwrap();
    let ctx = Context::new(date(2026, 9, 22, 22, 30));
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 9, 22, 0, 0))
    );
    assert_eq!(ctx.timezone(), chrono_tz::UTC);
}

#[test]
fn a_month_step_keeps_local_wall_clock_across_a_dst_change() {
    let schema = Schema::new().with_field("opened", Type::Date);
    let compiled = compile(r#"date_add(opened, 1, "months")"#, &schema).unwrap();

    // 2026-03-01T12:00 EST (-05) == 17:00Z; one local month later is
    // 2026-04-01T12:00 EDT (-04) == 16:00Z — the wall clock, not the offset,
    // is what a month step preserves.
    let ctx = Context::new(date(2026, 3, 1, 0, 0))
        .with_timezone(America::New_York)
        .with_field("opened", Value::Date(date(2026, 3, 1, 17, 0)));
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 4, 1, 16, 0))
    );

    // Without a zone the same step is the UTC calendar's, unchanged from
    // before BRU-C4.
    let utc_ctx = Context::new(date(2026, 3, 1, 0, 0))
        .with_field("opened", Value::Date(date(2026, 3, 1, 17, 0)));
    assert_eq!(
        compiled.eval(&utc_ctx).unwrap(),
        Value::Date(date(2026, 4, 1, 17, 0))
    );
}

#[test]
fn a_month_step_into_a_dst_gap_lands_after_the_gap() {
    let schema = Schema::new().with_field("opened", Type::Date);
    let compiled = compile(r#"date_add(opened, 1, "months")"#, &schema).unwrap();

    // 2026-02-08T02:30 EST == 07:30Z; 2026-03-08T02:30 does not exist in New
    // York (02:00 -> 03:00), so the step resolves an hour on, to 03:30 EDT
    // == 07:30Z, rather than failing as out of range.
    let ctx = Context::new(date(2026, 2, 8, 0, 0))
        .with_timezone(America::New_York)
        .with_field("opened", Value::Date(date(2026, 2, 8, 7, 30)));
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 3, 8, 7, 30))
    );
}

#[test]
fn a_month_step_into_a_dst_overlap_takes_the_earlier_instant() {
    let schema = Schema::new().with_field("opened", Type::Date);
    let compiled = compile(r#"date_add(opened, 1, "months")"#, &schema).unwrap();

    // 2026-10-01T01:30 EDT == 05:30Z; 2026-11-01T01:30 happens twice in New
    // York, and the step takes the first (EDT) one, 05:30Z.
    let ctx = Context::new(date(2026, 10, 1, 0, 0))
        .with_timezone(America::New_York)
        .with_field("opened", Value::Date(date(2026, 10, 1, 5, 30)));
    assert_eq!(
        compiled.eval(&ctx).unwrap(),
        Value::Date(date(2026, 11, 1, 5, 30))
    );
}

#[test]
fn month_difference_reads_local_calendar_fields() {
    let schema = Schema::new()
        .with_field("a", Type::Date)
        .with_field("b", Type::Date);
    let compiled = compile(r#"date_diff(a, b, "months")"#, &schema).unwrap();

    // a is local 2026-05-01T01:30, b is local 2026-04-01T00:30 in Kolkata
    // (+05:30), so the local calendar says one whole month while the UTC
    // calendar (Apr 30 vs Mar 31) says none.
    let kolkata = Context::new(date(2026, 1, 1, 0, 0))
        .with_timezone(Asia::Kolkata)
        .with_field("a", Value::Date(date(2026, 4, 30, 20, 0)))
        .with_field("b", Value::Date(date(2026, 3, 31, 19, 0)));
    assert_eq!(compiled.eval(&kolkata).unwrap(), Value::Number(1.0));

    let utc = Context::new(date(2026, 1, 1, 0, 0))
        .with_field("a", Value::Date(date(2026, 4, 30, 20, 0)))
        .with_field("b", Value::Date(date(2026, 3, 31, 19, 0)));
    assert_eq!(compiled.eval(&utc).unwrap(), Value::Number(0.0));
}

#[test]
fn an_unknown_zone_name_is_a_typed_error() {
    let err = Context::new(date(2026, 9, 22, 22, 30))
        .with_timezone_name("Mars/Olympus")
        .unwrap_err();
    assert_eq!(err, RulesError::UnknownTimezone("Mars/Olympus".to_owned()));
    assert_eq!(err.code(), "rules.context.unknown_timezone");

    // A real name parses, and its zone is the one requested.
    let ctx = Context::new(date(2026, 9, 22, 22, 30))
        .with_timezone_name("Asia/Riyadh")
        .unwrap();
    assert_eq!(ctx.timezone(), Asia::Riyadh);
}
