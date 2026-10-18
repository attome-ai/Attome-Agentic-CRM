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

async fn insert_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("cal-{id}@test.local"))
    .bind(format!("cal-{id}"))
    .execute(db)
    .await
    .expect("insert user");
    id
}

async fn assign(db: &DbPool, subject_type: &str, subject: Uuid, calendar: Uuid) {
    sqlx::query(
        "INSERT INTO calendar_assignment (subject_type, subject_id, calendar_id) VALUES ($1, $2, $3) \
         ON CONFLICT (subject_type, subject_id) DO UPDATE SET calendar_id = EXCLUDED.calendar_id",
    )
    .bind(subject_type)
    .bind(subject)
    .bind(calendar)
    .execute(db)
    .await
    .expect("assign calendar");
}

async fn join_team(db: &DbPool, user: Uuid, team: Uuid) {
    // The membership's team must exist (user_account_mm_team_team_ref_fkey).
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(team)
        .bind(format!("calendar-test-{team}"))
        .execute(db)
        .await
        .expect("create team");
    sqlx::query("INSERT INTO user_account_mm_team (user_ref, team_ref) VALUES ($1, $2)")
        .bind(user)
        .bind(team)
        .execute(db)
        .await
        .expect("join team");
}

#[tokio::test]
async fn user_assignment_wins_over_team() {
    let db = skip_if_no_db!(test_db().await);
    let team_cal = insert_calendar(
        &db,
        &["sun"],
        json!({ "sun": [{ "start_minute": 480, "end_minute": 960 }] }),
        None,
    )
    .await;
    let own_cal = insert_calendar(
        &db,
        &["mon"],
        json!({ "mon": [{ "start_minute": 480, "end_minute": 960 }] }),
        None,
    )
    .await;
    let user = insert_user(&db).await;
    let team = Uuid::now_v7();
    join_team(&db, user, team).await;
    assign(&db, "team", team, team_cal).await;
    assign(&db, "user", user, own_cal).await;
    let resolved = attome_core::calendar::resolve_calendar_id_for_user(&db, user)
        .await
        .unwrap();
    assert_eq!(resolved, Some(own_cal));
}

#[tokio::test]
async fn team_assignment_used_when_no_user_assignment() {
    let db = skip_if_no_db!(test_db().await);
    let first = insert_calendar(
        &db,
        &["sun"],
        json!({ "sun": [{ "start_minute": 480, "end_minute": 960 }] }),
        None,
    )
    .await;
    let second = insert_calendar(
        &db,
        &["mon"],
        json!({ "mon": [{ "start_minute": 480, "end_minute": 960 }] }),
        None,
    )
    .await;
    let user = insert_user(&db).await;
    let (low, high) = {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        if a < b { (a, b) } else { (b, a) }
    };
    join_team(&db, user, high).await;
    join_team(&db, user, low).await;
    assign(&db, "team", high, second).await;
    assign(&db, "team", low, first).await;
    let resolved = attome_core::calendar::resolve_calendar_id_for_user(&db, user)
        .await
        .unwrap();
    assert_eq!(
        resolved,
        Some(first),
        "the lowest team id with an assignment"
    );
}

#[tokio::test]
async fn falls_back_to_default() {
    let db = skip_if_no_db!(test_db().await);
    let user = insert_user(&db).await;
    let resolved = attome_core::calendar::resolve_calendar_id_for_user(&db, user)
        .await
        .unwrap();
    let default = attome_core::calendar::default_calendar_id(&db)
        .await
        .unwrap();
    assert_eq!(resolved, default);
}
