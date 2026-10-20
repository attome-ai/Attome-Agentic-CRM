//! E6-T4: the daily deliverability rollup is idempotent — running a day
//! twice leaves the same rows and totals — and splits by mailbox provider.
//!
//! `communication` and `communication_event` are provisioned here (boot
//! provisions them from their platform changesets); fixture rows are direct
//! SQL against this binary's throwaway database (guidelines §4's test
//! exemption). Each run uses its own sending domain, so other tests' rows
//! on the same day do not disturb the assertions.
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test deliverability_rollup"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use attome_testkit::skip_if_no_db;
use chrono::NaiveDate;
use sqlx::PgPool;
use uuid::Uuid;

async fn provision(db: &PgPool, name: &str, fields: &[(&str, &str)]) {
    let id = attome_metadata::provision::ensure_entity(db, name, name, None, false)
        .await
        .unwrap_or_else(|e| panic!("ensure {name}: {e}"));
    for (field, field_type) in fields {
        attome_metadata::provision::ensure_attribute(
            db, id, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure {name}.{field}: {e}"));
    }
}

async fn test_db() -> Option<PgPool> {
    let db = attome_testkit::migrated_pool(5).await?;
    provision(
        &db,
        "communication",
        &[
            ("entity_name", "text"),
            ("record_id", "text"),
            ("channel", "text"),
            ("to_addresses", "text"),
            ("message_id", "text"),
        ],
    )
    .await;
    provision(
        &db,
        "communication_event",
        &[("event_type", "text"), ("occurred_at", "date")],
    )
    .await;
    // The platform's column is a lookup (uuid) to the communication.
    sqlx::query("ALTER TABLE communication_event ADD COLUMN IF NOT EXISTS communication_id uuid")
        .execute(&db)
        .await
        .expect("communication_id column");
    Some(db)
}

async fn message(db: &PgPool, sending: &str, to: &str, events: &[&str], day: &str) {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO communication (id, entity_name, record_id, channel, to_addresses, message_id) \
         VALUES ($1, 'contact', $2, 'email', $3, $4)",
    )
    .bind(id)
    .bind(Uuid::now_v7().to_string())
    .bind(to)
    .bind(format!("<{}@{sending}>", Uuid::now_v7().simple()))
    .execute(db)
    .await
    .expect("insert communication");
    for event in events {
        sqlx::query(
            "INSERT INTO communication_event (id, communication_id, event_type, occurred_at) \
             VALUES ($1, $2, $3, ($4 || 'T10:00:00Z')::timestamptz)",
        )
        .bind(Uuid::now_v7())
        .bind(id)
        .bind(event)
        .bind(day)
        .execute(db)
        .await
        .expect("insert event");
    }
}

type Row = (String, i64, i64, i64, i64);

async fn rows(db: &PgPool, day: NaiveDate, sending: &str) -> Vec<Row> {
    sqlx::query_as(
        "SELECT mailbox_provider, sent, delivered, bounced, opened \
           FROM marketing_deliverability_daily \
          WHERE day = $1 AND sending_domain = $2 ORDER BY mailbox_provider",
    )
    .bind(day)
    .bind(sending)
    .fetch_all(db)
    .await
    .unwrap()
}

#[tokio::test]
async fn rollup_day_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let sending = format!("m{}.example.com", Uuid::now_v7().simple());
    let day = NaiveDate::from_ymd_opt(2026, 9, 15).unwrap();
    message(
        &db,
        &sending,
        "a@gmail.com",
        &["sent", "delivered", "opened"],
        "2026-09-15",
    )
    .await;
    message(
        &db,
        &sending,
        "b@googlemail.com",
        &["sent", "delivered"],
        "2026-09-15",
    )
    .await;
    message(
        &db,
        &sending,
        "c@hotmail.com",
        &["sent", "bounced"],
        "2026-09-15",
    )
    .await;
    // Another day's event is not this day's.
    message(&db, &sending, "d@gmail.com", &["sent"], "2026-09-16").await;

    attome_marketing::deliverability::rollup::rollup_day(&db, day)
        .await
        .expect("first rollup");
    let first = rows(&db, day, &sending).await;
    assert_eq!(
        first,
        vec![
            ("gmail".to_owned(), 2, 2, 0, 1),
            ("outlook".to_owned(), 1, 0, 1, 0),
        ]
    );

    attome_marketing::deliverability::rollup::rollup_day(&db, day)
        .await
        .expect("second rollup");
    assert_eq!(rows(&db, day, &sending).await, first);
}
