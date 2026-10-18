//! Z12-T4: `load_calendar` on a migrated throwaway database. A child calendar
//! inherits its parent's holidays and hours; a changed definition bumps the
//! calendar's content version once, and an unchanged one keeps it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-core --test calendar_load
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::calendar::load_calendar;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::NaiveDate;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

async fn insert_calendar(
    db: &DbPool,
    working_days: &[&str],
    hours: serde_json::Value,
    parent: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    let days: Vec<String> = working_days.iter().map(|d| (*d).to_owned()).collect();
    sqlx::query(
        "INSERT INTO calendar (id, name, tz, working_days, hours, parent_calendar_id, owner_layer) \
         VALUES ($1, $2, 'Asia/Riyadh', $3, $4, $5, 'platform')",
    )
    .bind(id)
    .bind(format!("cal-{id}"))
    .bind(&days)
    .bind(hours)
    .bind(parent)
    .execute(db)
    .await
    .expect("insert calendar");
    id
}

fn sun_thu() -> serde_json::Value {
    let day = json!([{ "start_minute": 480, "end_minute": 1020 }]);
    json!({ "sun": day, "mon": day, "tue": day, "wed": day, "thu": day })
}

#[tokio::test]
async fn parent_holidays_inherited() {
    let db = skip_if_no_db!(test_db().await);
    let parent = insert_calendar(&db, &["sun", "mon", "tue", "wed", "thu"], sun_thu(), None).await;
    let holiday = NaiveDate::from_ymd_opt(2026, 9, 23).unwrap();
    sqlx::query(
        "INSERT INTO calendar_holiday (calendar_id, name, holiday_date, owner_layer) \
         VALUES ($1, 'National Day', $2, 'platform')",
    )
    .bind(parent)
    .bind(holiday)
    .execute(&db)
    .await
    .unwrap();
    let child = insert_calendar(&db, &[], json!({}), Some(parent)).await;

    let loaded = load_calendar(&db, child).await.unwrap().unwrap();
    assert!(loaded.calendar.holidays().contains(&holiday));
    assert_eq!(loaded.calendar.working_days().len(), 5);
    assert_eq!(loaded.version, 1);

    // A chain that loops is refused, not followed forever.
    sqlx::query("UPDATE calendar SET parent_calendar_id = $1 WHERE id = $2")
        .bind(child)
        .bind(parent)
        .execute(&db)
        .await
        .unwrap();
    assert!(load_calendar(&db, child).await.unwrap().is_err());
}

#[tokio::test]
async fn changed_definition_bumps_version() {
    let db = skip_if_no_db!(test_db().await);
    let id = insert_calendar(&db, &["sun", "mon", "tue", "wed", "thu"], sun_thu(), None).await;
    let first = load_calendar(&db, id).await.unwrap().unwrap();
    assert_eq!(first.version, 1);
    let again = load_calendar(&db, id).await.unwrap().unwrap();
    assert_eq!(again.version, 1, "an unchanged calendar keeps its version");

    let later = json!([{ "start_minute": 540, "end_minute": 1080 }]);
    sqlx::query("UPDATE calendar SET hours = jsonb_set(hours, '{sun}', $2) WHERE id = $1")
        .bind(id)
        .bind(later)
        .execute(&db)
        .await
        .unwrap();
    let changed = load_calendar(&db, id).await.unwrap().unwrap();
    assert_eq!(changed.version, 2);
    assert_ne!(changed.content_hash, first.content_hash);
    let current: i32 = sqlx::query_scalar("SELECT current_version FROM calendar WHERE id = $1")
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(current, 2);
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM calendar_version WHERE calendar_id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(rows, 2);
}
