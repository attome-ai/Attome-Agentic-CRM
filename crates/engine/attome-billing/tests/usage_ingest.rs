//! F3-T7: a repeated usage batch is stored once.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::usage::{IngestResult, UsageIn, insert_batch};
use attome_testkit::migrated_pool_or_skip;
use chrono::Utc;
use uuid::Uuid;

#[tokio::test]
async fn repeated_key_is_ignored() {
    let pool = migrated_pool_or_skip!(2);
    let line = Uuid::now_v7();
    let at = Utc::now();
    let batch = vec![
        UsageIn {
            subscription_line_id: line,
            metric: "api_calls".into(),
            quantity: 5.0,
            occurred_at: at,
            idempotency_key: "k-1".into(),
        },
        UsageIn {
            subscription_line_id: line,
            metric: "api_calls".into(),
            quantity: 7.0,
            occurred_at: at,
            idempotency_key: "k-2".into(),
        },
    ];

    for expected in [
        IngestResult {
            accepted: 2,
            duplicates: 0,
        },
        IngestResult {
            accepted: 0,
            duplicates: 2,
        },
    ] {
        let mut tx = attome_db::tx::begin(&pool).await.expect("begin");
        let result = insert_batch(&mut tx, &batch).await.expect("insert");
        tx.commit().await.expect("commit");
        assert_eq!(result, expected);
    }

    let stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM billing_usage_record WHERE subscription_line_id = $1",
    )
    .bind(line)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(stored, 2, "the batch is stored once");
    let total: f64 = sqlx::query_scalar(
        "SELECT quantity::float8 FROM billing_usage_daily WHERE subscription_line_id = $1",
    )
    .bind(line)
    .fetch_one(&pool)
    .await
    .expect("daily total");
    assert!(
        (total - 12.0).abs() < 1e-9,
        "the daily total counts each record once: {total}"
    );
}
